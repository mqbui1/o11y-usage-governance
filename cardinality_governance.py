#!/usr/bin/env python3
"""
Metric Cardinality Governance for Splunk Observability Cloud

Scans an org for MTS explosions, attributes cost to teams/services,
and uses Claude to recommend rollups and fixes.

Usage:
  python3 cardinality_governance.py scan
  python3 cardinality_governance.py report
  python3 cardinality_governance.py watch
  python3 cardinality_governance.py rollup --metric <name>
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import boto3
import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REALM  = os.environ.get("SPLUNK_REALM", "us1")
TOKEN  = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
INGEST_TOKEN = os.environ.get("SPLUNK_INGEST_TOKEN", "")

API_BASE    = f"https://api.{REALM}.signalfx.com"
INGEST_BASE = f"https://ingest.{REALM}.signalfx.com"

BEDROCK_PROFILE = "arn:aws:bedrock:us-west-2:387769110234:application-inference-profile/fky19kpnw2m7"

# Thresholds
CRITICAL_MTS_COUNT    = 10_000   # single metric MTS count — critical
HIGH_MTS_COUNT        = 1_000    # single metric MTS count — high
MEDIUM_MTS_COUNT      = 500      # single metric MTS count — medium
CRITICAL_DIM_VALUES   = 10_000   # unique values for a single dimension — critical
HIGH_DIM_VALUES       = 1_000    # unique values for a single dimension — high

# Regex patterns that indicate high-cardinality anti-patterns
CARDINALITY_PATTERNS = [
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "UUID"),
    (re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),                                   "IP address"),
    (re.compile(r"^\d{10,13}$"),                                                              "Timestamp/epoch"),
    (re.compile(r"^[0-9a-f]{32}$", re.I),                                                    "MD5 hash"),
    (re.compile(r"^[0-9a-f]{40}$", re.I),                                                    "SHA1 hash"),
    (re.compile(r".{100,}"),                                                                  "Very long string"),
]

REPORTS_DIR  = Path("reports")
STATE_DB     = Path("cardinality_state.db")
TREND_GROWTH_WARN    = 0.20   # flag if MTS grew >20% since last scan
REMEDIATION_DROP_PCT = 0.50   # mark resolved if MTS dropped >50% vs peak

# Cost estimation — override with MTS_COST_PER_MONTH env var
# Default: $0.002 per MTS per month (conservative mid-tier estimate)
MTS_COST_PER_MONTH = float(os.environ.get("MTS_COST_PER_MONTH", "0.002"))

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def api_get(path, params=None):
    headers = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}
    resp = requests.get(f"{API_BASE}{path}", headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def api_post(path, body):
    headers = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}
    resp = requests.post(f"{API_BASE}{path}", headers=headers, json=body, timeout=30)
    resp.raise_for_status()
    return resp.json()


def ingest_event(event_type, dimensions, properties):
    if not INGEST_TOKEN:
        return
    headers = {"X-SF-TOKEN": INGEST_TOKEN, "Content-Type": "application/json"}
    payload = [{
        "eventType": event_type,
        "dimensions": dimensions,
        "properties": properties,
        "timestamp": int(time.time() * 1000),
    }]
    try:
        requests.post(f"{INGEST_BASE}/v2/event", headers=headers, json=payload, timeout=10)
    except Exception:
        pass


def execute_signalflow(program, duration_ms=60000):
    """Execute a SignalFlow program and return last values."""
    url = f"https://stream.{REALM}.signalfx.com/v2/signalflow/execute"
    params = {
        "start": int(time.time() * 1000) - duration_ms,
        "stop":  int(time.time() * 1000),
        "immediate": "true",
    }
    headers = {"X-SF-TOKEN": TOKEN, "Content-Type": "text/plain"}
    try:
        resp = requests.post(url, headers=headers, params=params, data=program, timeout=30, stream=True)
        results = {}
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                msg = json.loads(line)
                if msg.get("type") == "data":
                    for tsid, val in msg.get("data", {}).items():
                        if val is not None:
                            results[tsid] = val
            except Exception:
                continue
        return results
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Claude helper
# ---------------------------------------------------------------------------

def call_claude(prompt):
    client = boto3.client("bedrock-runtime", region_name="us-west-2")
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }
    resp = client.invoke_model(modelId=BEDROCK_PROFILE, body=json.dumps(body))
    return json.loads(resp["body"].read())["content"][0]["text"]


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Trend tracking (SQLite)
# ---------------------------------------------------------------------------

def db_connect():
    conn = sqlite3.connect(STATE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at  TEXT NOT NULL,
            realm       TEXT NOT NULL,
            metric      TEXT NOT NULL,
            mts_count   INTEGER NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS remediations (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            realm         TEXT NOT NULL,
            metric        TEXT NOT NULL,
            peak_mts      INTEGER NOT NULL,
            peak_at       TEXT NOT NULL,
            resolved_mts  INTEGER NOT NULL,
            resolved_at   TEXT NOT NULL,
            reduction_pct REAL NOT NULL,
            manual        INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ignored (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            realm      TEXT NOT NULL,
            pattern    TEXT NOT NULL,
            reason     TEXT NOT NULL DEFAULT '',
            ignored_at TEXT NOT NULL,
            UNIQUE(realm, pattern)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_summaries (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at   TEXT NOT NULL,
            realm        TEXT NOT NULL,
            total_metrics INTEGER NOT NULL,
            total_mts    INTEGER NOT NULL,
            critical     INTEGER NOT NULL DEFAULT 0,
            high         INTEGER NOT NULL DEFAULT 0,
            medium       INTEGER NOT NULL DEFAULT 0,
            ignored      INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    return conn


def db_save_scan(findings):
    """Persist current scan results to SQLite."""
    conn = db_connect()
    ts = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO scans (scanned_at, realm, metric, mts_count) VALUES (?, ?, ?, ?)",
        [(ts, REALM, f["metric"], f["mts_count"]) for f in findings]
    )
    conn.commit()
    conn.close()


def db_get_previous(metric_name):
    """Return (mts_count, scanned_at) from the most recent prior scan for this metric."""
    if not STATE_DB.exists():
        return None, None
    conn = db_connect()
    row = conn.execute(
        """SELECT mts_count, scanned_at FROM scans
           WHERE realm=? AND metric=?
           ORDER BY scanned_at DESC LIMIT 1""",
        (REALM, metric_name)
    ).fetchone()
    conn.close()
    return (row[0], row[1]) if row else (None, None)


def db_get_history(metric_name, limit=10):
    """Return list of (scanned_at, mts_count) for a metric, newest first."""
    if not STATE_DB.exists():
        return []
    conn = db_connect()
    rows = conn.execute(
        """SELECT scanned_at, mts_count FROM scans
           WHERE realm=? AND metric=?
           ORDER BY scanned_at DESC LIMIT ?""",
        (REALM, metric_name, limit)
    ).fetchall()
    conn.close()
    return rows


def db_get_peak(metric_name):
    """Return (peak_mts, scanned_at) — the highest MTS count ever seen for this metric."""
    if not STATE_DB.exists():
        return None, None
    conn = db_connect()
    row = conn.execute(
        """SELECT mts_count, scanned_at FROM scans
           WHERE realm=? AND metric=?
           ORDER BY mts_count DESC LIMIT 1""",
        (REALM, metric_name)
    ).fetchone()
    conn.close()
    return (row[0], row[1]) if row else (None, None)


def db_mark_resolved(metric_name, peak_mts, peak_at, current_mts, manual=False):
    """Record that a metric's cardinality has been successfully remediated."""
    conn = db_connect()
    ts = datetime.now(timezone.utc).isoformat()
    reduction_pct = round((peak_mts - current_mts) / peak_mts * 100, 1)
    conn.execute(
        """INSERT INTO remediations
               (realm, metric, peak_mts, peak_at, resolved_mts, resolved_at, reduction_pct, manual)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (REALM, metric_name, peak_mts, peak_at, current_mts, ts, reduction_pct, int(manual))
    )
    conn.commit()
    conn.close()
    return reduction_pct


def db_get_resolved():
    """Return all resolved findings for this realm, most recently resolved first."""
    if not STATE_DB.exists():
        return []
    conn = db_connect()
    rows = conn.execute(
        """SELECT metric, peak_mts, peak_at, resolved_mts, resolved_at, reduction_pct, manual
           FROM remediations
           WHERE realm=?
           ORDER BY resolved_at DESC""",
        (REALM,)
    ).fetchall()
    conn.close()
    return rows


def db_is_resolved(metric_name):
    """Return True if this metric has been marked resolved and hasn't re-exploded since."""
    if not STATE_DB.exists():
        return False
    conn = db_connect()
    row = conn.execute(
        """SELECT resolved_at FROM remediations
           WHERE realm=? AND metric=?
           ORDER BY resolved_at DESC LIMIT 1""",
        (REALM, metric_name)
    ).fetchone()
    conn.close()
    return row is not None


# ---------------------------------------------------------------------------
# Ignore list helpers
# ---------------------------------------------------------------------------

def db_ignore(pattern, reason=""):
    """Add a metric name or glob pattern to the ignore list."""
    conn = db_connect()
    ts = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO ignored (realm, pattern, reason, ignored_at) VALUES (?, ?, ?, ?)",
            (REALM, pattern, reason, ts)
        )
        conn.commit()
    finally:
        conn.close()


def db_unignore(pattern):
    """Remove a pattern from the ignore list."""
    conn = db_connect()
    conn.execute("DELETE FROM ignored WHERE realm=? AND pattern=?", (REALM, pattern))
    conn.commit()
    conn.close()


def db_get_ignored():
    """Return list of (pattern, reason, ignored_at) for this realm."""
    if not STATE_DB.exists():
        return []
    conn = db_connect()
    rows = conn.execute(
        "SELECT pattern, reason, ignored_at FROM ignored WHERE realm=? ORDER BY ignored_at",
        (REALM,)
    ).fetchall()
    conn.close()
    return rows


def is_ignored(metric_name, ignored_patterns):
    """Return True if metric_name matches any ignore pattern (exact or prefix glob)."""
    import fnmatch
    for pattern, _, _ in ignored_patterns:
        if fnmatch.fnmatch(metric_name, pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# Scan summary helpers
# ---------------------------------------------------------------------------

def db_save_summary(total_metrics, total_mts, critical, high, medium, ignored_count):
    """Persist a per-scan summary row."""
    conn = db_connect()
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO scan_summaries
               (scanned_at, realm, total_metrics, total_mts, critical, high, medium, ignored)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts, REALM, total_metrics, total_mts, critical, high, medium, ignored_count)
    )
    conn.commit()
    conn.close()


def db_get_scan_history(limit=30):
    """Return the last N scan summaries, newest first."""
    if not STATE_DB.exists():
        return []
    conn = db_connect()
    rows = conn.execute(
        """SELECT scanned_at, total_metrics, total_mts, critical, high, medium, ignored
           FROM scan_summaries WHERE realm=?
           ORDER BY scanned_at DESC LIMIT ?""",
        (REALM, limit)
    ).fetchall()
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# Org info
# ---------------------------------------------------------------------------

def fetch_org_info():
    """Get org-level MTS usage and limits."""
    try:
        return api_get("/v2/organization")
    except Exception as e:
        print(f"  Warning: could not fetch org info: {e}")
        return {}


def fetch_tokens():
    """Fetch org tokens to map ingest source → team."""
    try:
        result = api_get("/v2/token", params={"limit": 100})
        return result.get("results", [])
    except Exception:
        return []


def fetch_metrics(limit=None):
    """Fetch all metrics with pagination — returns complete list."""
    metrics = []
    page_size = 100
    offset = None
    fetched = 0

    while True:
        params = {"limit": page_size}
        if offset:
            params["offset"] = offset

        try:
            result = api_get("/v2/metric", params=params)
        except Exception as e:
            print(f"  Warning: metric fetch error: {e}")
            break

        page = result.get("results", [])
        metrics.extend(page)
        fetched += len(page)

        if limit and fetched >= limit:
            metrics = metrics[:limit]
            break

        # Check for next page via count vs fetched
        total = result.get("count", 0)
        if len(page) < page_size or fetched >= total:
            break

        offset = fetched

    return metrics


def fetch_mts_for_metric(metric_name, limit=10000):
    """Fetch MTS count and sample dimensions for a metric."""
    try:
        result = api_get("/v2/metrictimeseries", params={
            "query": f"sf_metric:{metric_name}",
            "limit": limit,
        })
        return result.get("results", [])
    except Exception:
        return []


def search_metrics_by_query(query="*", limit=200):
    """Search metrics matching a query."""
    try:
        result = api_get("/v2/metric", params={"query": query, "limit": limit})
        return result.get("results", [])
    except Exception:
        return []


def detect_cardinality_pattern(value):
    """Return pattern name if value matches a high-cardinality anti-pattern."""
    for pattern, name in CARDINALITY_PATTERNS:
        if pattern.match(str(value)):
            return name
    return None


def analyze_dimensions(mts_list):
    """
    Given a list of MTS objects, find high-cardinality dimensions.
    Returns dict: dim_name -> {count, sample_values, pattern}
    """
    dim_values = defaultdict(set)
    skip_dims = {"sf_metric", "sf_type", "_sf_organizationID", "sf_originatingMetric"}

    for mts in mts_list:
        for dim, val in mts.get("dimensions", {}).items():
            if dim in skip_dims:
                continue
            dim_values[dim].add(str(val))

    results = {}
    for dim, values in dim_values.items():
        count = len(values)
        if count < 10:
            continue
        samples = list(values)[:5]
        pattern = None
        for v in samples:
            p = detect_cardinality_pattern(v)
            if p:
                pattern = p
                break
        results[dim] = {
            "unique_values": count,
            "sample_values": samples,
            "pattern": pattern,
        }

    return dict(sorted(results.items(), key=lambda x: -x[1]["unique_values"]))


def severity(mts_count):
    if mts_count >= CRITICAL_MTS_COUNT:
        return "CRITICAL"
    elif mts_count >= HIGH_MTS_COUNT:
        return "HIGH"
    elif mts_count >= MEDIUM_MTS_COUNT:
        return "MEDIUM"
    return "LOW"


def estimate_cost(mts_count):
    """Return estimated monthly cost string for a given MTS count."""
    cost = mts_count * MTS_COST_PER_MONTH
    if cost >= 1000:
        return f"~${cost:,.0f}/mo"
    elif cost >= 1:
        return f"~${cost:.2f}/mo"
    else:
        return f"~${cost:.4f}/mo"


# Instrumentation source rules: (metric prefix/pattern, source label, description)
INSTRUMENTATION_SOURCES = [
    # OTel Collector internal metrics
    (re.compile(r"^otelcol_"),                        "OTel Collector",      "Emitted by the OpenTelemetry Collector process itself (internal telemetry)"),
    (re.compile(r"^otel\.sdk\."),                     "OTel SDK",            "Emitted by the OpenTelemetry SDK runtime (language agent self-metrics)"),
    # Splunk-specific
    (re.compile(r"^sf\."),                             "Splunk Agent",        "Emitted by Splunk Infrastructure Monitoring agent"),
    (re.compile(r"^splunk\."),                         "Splunk Platform",     "Emitted by Splunk platform components"),
    # Kubernetes / infra
    (re.compile(r"^k8s\."),                            "Kubernetes",          "Kubernetes cluster/node/pod metrics via kubelet or kube-state-metrics"),
    (re.compile(r"^container\."),                      "Container Runtime",   "Container runtime metrics (Docker/containerd)"),
    (re.compile(r"^system\."),                         "Host / OS",           "Host-level system metrics (CPU, memory, disk, network)"),
    (re.compile(r"^process\."),                        "Host / OS",           "Process-level metrics from the host metrics receiver"),
    # JVM / language runtimes
    (re.compile(r"^jvm\."),                            "JVM",                 "Java Virtual Machine runtime metrics (heap, GC, threads)"),
    (re.compile(r"^process\.runtime\.jvm\."),          "JVM",                 "OTel semantic convention JVM runtime metrics"),
    (re.compile(r"^nodejs\."),                         "Node.js Runtime",     "Node.js runtime metrics"),
    (re.compile(r"^python\."),                         "Python Runtime",      "Python runtime metrics"),
    # HTTP / web frameworks
    (re.compile(r"^http\."),                           "HTTP Instrumentation","HTTP client/server metrics from OTel HTTP semantic conventions"),
    # Databases
    (re.compile(r"^db\."),                             "Database Client",     "Database client metrics from OTel DB semantic conventions"),
    (re.compile(r"^mysql\."),                          "MySQL",               "MySQL database metrics"),
    (re.compile(r"^postgresql\."),                     "PostgreSQL",          "PostgreSQL database metrics"),
    (re.compile(r"^redis\."),                          "Redis",               "Redis metrics"),
    (re.compile(r"^mongodb\."),                        "MongoDB",             "MongoDB metrics"),
    # Messaging
    (re.compile(r"^messaging\."),                      "Messaging",           "Messaging system metrics (Kafka, RabbitMQ, etc.)"),
    (re.compile(r"^kafka\."),                          "Kafka",               "Apache Kafka metrics"),
    # Cloud providers
    (re.compile(r"^aws\."),                            "AWS",                 "AWS CloudWatch metrics"),
    (re.compile(r"^azure\."),                          "Azure",               "Azure Monitor metrics"),
    (re.compile(r"^gcp\."),                            "GCP",                 "Google Cloud Monitoring metrics"),
    # Behavioral baseline (our own framework)
    (re.compile(r"^behavioral_baseline\."),            "Behavioral Baseline Framework", "Custom metrics emitted by the behavioral anomaly detection framework"),
    # Generic custom
    (re.compile(r"^custom\."),                         "Custom (app)",        "Application-defined custom metric"),
]


def infer_instrumentation_source(metric_name, mts_list):
    """
    Infer the instrumentation source for a metric based on its name and dimensions.
    Returns (source_label, description).
    """
    # Check name-based rules first
    for pattern, label, desc in INSTRUMENTATION_SOURCES:
        if pattern.match(metric_name):
            return label, desc

    # Fallback: inspect dimensions for clues
    all_dims = set()
    for mts in mts_list[:20]:
        all_dims.update(mts.get("dimensions", {}).keys())

    if "k8s.pod.name" in all_dims or "k8s.namespace.name" in all_dims:
        return "Kubernetes (app)", "Application metric with Kubernetes resource attributes"
    if "host.name" in all_dims or "os.type" in all_dims:
        return "Host instrumentation", "Application metric with host resource attributes"
    if "service.name" in all_dims or "service.version" in all_dims:
        return "OTel SDK (app)", "Custom application metric instrumented via OTel SDK"

    return "Unknown / Custom", "Source could not be determined from metric name or dimensions"


def attribute_to_team(mts_list, tokens):
    """
    Best-effort attribution. Returns list of service name strings (for backward compat).
    Also populates a richer attribution dict accessible via attribute_detail().
    """
    services = set()
    for mts in mts_list[:100]:
        dims = mts.get("dimensions", {})
        for key in ["service.name", "service", "sf_service", "team", "owner"]:
            if key in dims:
                services.add(dims[key])
    return sorted(services) if services else ["unknown"]


def attribute_detail(mts_list):
    """
    Returns a rich attribution dict:
    {
      "services":     [...],
      "environments": [...],   # deployment.environment or service.namespace
      "namespaces":   [...],   # k8s.namespace.name
      "clusters":     [...],   # k8s.cluster.name
      "pods":         [...],   # k8s.pod.name (sample)
      "sdk":          "...",   # telemetry SDK info
    }
    """
    services     = set()
    environments = set()
    namespaces   = set()
    clusters     = set()
    pods         = set()
    sdk_versions = set()

    for mts in mts_list[:200]:
        dims = mts.get("dimensions", {})

        # Services
        for key in ["service.name", "service", "sf_service"]:
            if key in dims:
                services.add(dims[key])

        # Environments
        for key in ["deployment.environment", "environment", "sf_environment"]:
            if key in dims:
                environments.add(dims[key])
        # Fallback: service.namespace as environment proxy
        if not environments and "service.namespace" in dims:
            environments.add(dims["service.namespace"])

        # Kubernetes
        if "k8s.namespace.name" in dims:
            namespaces.add(dims["k8s.namespace.name"])
        if "k8s.cluster.name" in dims:
            clusters.add(dims["k8s.cluster.name"])
        if "k8s.pod.name" in dims:
            pods.add(dims["k8s.pod.name"])

        # SDK
        if "splunk.zc.method" in dims:
            sdk_versions.add(dims["splunk.zc.method"])
        elif "telemetry.sdk.name" in dims and "telemetry.sdk.version" in dims:
            sdk_versions.add(f"{dims['telemetry.sdk.name']}:{dims['telemetry.sdk.version']}")

    return {
        "services":     sorted(services)     or ["unknown"],
        "environments": sorted(environments) or [],
        "namespaces":   sorted(namespaces)   or [],
        "clusters":     sorted(clusters)     or [],
        "pods":         sorted(pods)[:5],     # sample only
        "sdk":          ", ".join(sorted(sdk_versions)) if sdk_versions else "",
    }


def scan_org(top_n=50, verbose=False):
    """
    Full org scan. Returns list of findings sorted by MTS count descending.
    Includes org limit awareness and week-over-week trend tracking.
    """
    print(f"\nScanning org (realm={REALM})...\n")

    org    = fetch_org_info()
    tokens = fetch_tokens()

    # Org MTS limit awareness
    mts_limit = org.get("mtsCategoryInfo", {}).get("mtsLimitThreshold") \
             or org.get("mtsLimit") \
             or org.get("numResourcesMonitored")
    if mts_limit:
        print(f"  Org MTS limit: {mts_limit:,}")

    # Load ignore list once before scanning
    ignored_patterns = db_get_ignored()
    if ignored_patterns:
        print(f"  Ignore list: {len(ignored_patterns)} pattern(s) active")

    # Fetch all metrics with pagination
    print("  Fetching metric catalog (paginated)...")
    metrics = fetch_metrics()

    if not metrics:
        print("  No metrics found. Check your token permissions.")
        return []

    print(f"  Found {len(metrics)} metrics. Analyzing top offenders...\n")

    findings = []

    for i, metric in enumerate(metrics):
        name   = metric.get("name", "")
        mtype  = metric.get("type", "gauge")
        custom = metric.get("custom", True)

        if verbose:
            print(f"  [{i+1}/{len(metrics)}] {name}")

        # Fetch MTS for this metric
        mts_list  = fetch_mts_for_metric(name, limit=10000)
        mts_count = len(mts_list)

        if mts_count == 0:
            continue

        # Skip ignored metrics
        if is_ignored(name, ignored_patterns):
            continue

        sev = severity(mts_count)
        if sev == "LOW" and not verbose:
            continue

        # Trend: compare to previous scan
        prev_count, prev_ts = db_get_previous(name)
        if prev_count is not None:
            growth_pct = (mts_count - prev_count) / prev_count if prev_count > 0 else 0
            trend = "NEW"    if prev_count == 0 else \
                    "GROWING" if growth_pct >= TREND_GROWTH_WARN else \
                    "FALLING" if growth_pct <= -TREND_GROWTH_WARN else \
                    "STABLE"
        else:
            prev_count = None
            growth_pct = None
            prev_ts    = None
            trend      = "NEW"

        # Auto-remediation detection: check if MTS dropped >50% vs historical peak
        peak_mts, peak_at = db_get_peak(name)
        auto_resolved = False
        if peak_mts and peak_mts > 0:
            drop_pct = (peak_mts - mts_count) / peak_mts
            if drop_pct >= REMEDIATION_DROP_PCT and not db_is_resolved(name):
                db_mark_resolved(name, peak_mts, peak_at, mts_count, manual=False)
                auto_resolved = True
                print(f"  [RESOLVED] {name}: {peak_mts:,} → {mts_count:,} MTS (-{int(drop_pct*100)}%)")

        # MTS limit % contribution
        limit_pct = round(mts_count / mts_limit * 100, 2) if mts_limit else None

        # Analyze dimensions
        dim_analysis  = analyze_dimensions(mts_list)
        attributed_to = attribute_to_team(mts_list, tokens)
        attribution   = attribute_detail(mts_list)
        instr_source, instr_desc = infer_instrumentation_source(name, mts_list)

        # Find worst offending dimension
        worst_dim      = None
        worst_dim_info = None
        for dim, info in dim_analysis.items():
            if worst_dim is None or info["unique_values"] > worst_dim_info["unique_values"]:
                worst_dim      = dim
                worst_dim_info = info

        findings.append({
            "metric":         name,
            "type":           mtype,
            "custom":         custom,
            "mts_count":      mts_count,
            "severity":       sev,
            "dimensions":     dim_analysis,
            "worst_dim":      worst_dim,
            "worst_dim_info": worst_dim_info,
            "attributed_to":  attributed_to,
            "instr_source":   instr_source,
            "instr_desc":     instr_desc,
            "attribution":    attribution,
            "prev_count":     prev_count,
            "prev_ts":        prev_ts,
            "growth_pct":     growth_pct,
            "trend":          trend,
            "limit_pct":      limit_pct,
            "auto_resolved":  auto_resolved,
            "peak_mts":       peak_mts,
            "peak_at":        peak_at,
        })

    # Sort by MTS count descending
    findings.sort(key=lambda x: -x["mts_count"])
    top = findings[:top_n]

    # Persist results for next run's trend comparison
    db_save_scan(top)

    # Save scan summary for history tracking
    n_critical = sum(1 for f in top if f["severity"] == "CRITICAL")
    n_high     = sum(1 for f in top if f["severity"] == "HIGH")
    n_medium   = sum(1 for f in top if f["severity"] == "MEDIUM")
    n_ignored  = sum(1 for m in metrics if is_ignored(m.get("name", ""), ignored_patterns))
    db_save_summary(len(metrics), sum(f["mts_count"] for f in top), n_critical, n_high, n_medium, n_ignored)

    return top


# ---------------------------------------------------------------------------
# Fix suggestion generator
# ---------------------------------------------------------------------------

def generate_fix_yaml(dim, metrics, dim_info):
    """
    Generate ready-to-paste OTel Collector processor YAML to drop or hash
    a high-cardinality dimension for a group of metrics.

    Returns a dict with keys:
      filter_processor   — drops the dimension entirely
      transform_processor — hashes the value (preserves grouping, kills cardinality)
      signalflow_rollup   — SignalFlow snippet that aggregates away the dimension
    """
    metric_list = "\n".join(f"            - '{m}'" for m in sorted(metrics))
    pattern_note = f"  # anti-pattern: {dim_info['pattern']}" if dim_info.get("pattern") else ""
    unique_vals = dim_info.get("unique_values", "?")

    # --- filter/transform processor: delete the attribute ---
    filter_yaml = f"""\
# OTel Collector processor — drop `{dim}` from {len(metrics)} metric(s)
# Dimension has {unique_vals} unique values{(' (' + dim_info['pattern'] + ')') if dim_info.get('pattern') else ''}
# Effect: eliminates the cardinality explosion; metric is still reported per remaining dimensions.
processors:
  transform/drop_{dim.replace('.', '_')}:
    metric_statements:
      - context: datapoint
        statements:
          - delete_key(attributes, "{dim}"){pattern_note}
        # Apply only to these metrics (remove 'include' block to apply to all):
        include:
          match_type: strict
          metric_names:
{metric_list}

service:
  pipelines:
    metrics:
      processors: [transform/drop_{dim.replace('.', '_')}, ...]"""

    # --- transform processor: hash the value (keeps some grouping signal) ---
    transform_yaml = f"""\
# Alternative: hash `{dim}` instead of dropping — preserves cardinality grouping signal
# at low cost. Use when you still need to correlate across restarts/redeploys.
processors:
  transform/hash_{dim.replace('.', '_')}:
    metric_statements:
      - context: datapoint
        statements:
          - set(attributes["{dim}"], SHA256(attributes["{dim}"]))
        include:
          match_type: strict
          metric_names:
{metric_list}"""

    # --- SignalFlow rollup that aggregates away the dimension ---
    return {
        "filter_processor": filter_yaml,
        "transform_processor": transform_yaml,
    }




def generate_remediation(finding):
    """Use Claude to generate a specific remediation recommendation."""
    dim_summary = ""
    for dim, info in list(finding["dimensions"].items())[:5]:
        pattern_note = f" (looks like {info['pattern']})" if info["pattern"] else ""
        dim_summary += f"  - {dim}: {info['unique_values']} unique values{pattern_note}, e.g. {info['sample_values'][:3]}\n"

    prompt = f"""You are a Splunk Observability Cloud expert specializing in metric cardinality optimization.

A customer has a metric with a cardinality problem:

Metric: {finding['metric']}
Type: {finding['type']}
Custom metric: {finding['custom']}
Total MTS count: {finding['mts_count']}
Severity: {finding['severity']}
Instrumentation source: {finding['instr_source']} — {finding['instr_desc']}
Services: {', '.join(finding.get('attribution', {}).get('services', finding['attributed_to']))}
Environments: {', '.join(finding.get('attribution', {}).get('environments', [])) or 'unknown'}
Clusters: {', '.join(finding.get('attribution', {}).get('clusters', [])) or 'unknown'}
Namespaces: {', '.join(finding.get('attribution', {}).get('namespaces', [])) or 'unknown'}
SDK: {finding.get('attribution', {}).get('sdk', 'unknown')}

High-cardinality dimensions:
{dim_summary}

Provide a concise remediation recommendation that includes:
1. Root cause (1 sentence — which dimension is the problem and why)
2. Recommended fix (be specific: OTel SDK attribute filter config, SignalFlow rollup, or metric rename)
3. A concrete SignalFlow rollup example if applicable (using data() and sum(by=[...]))
4. Estimated MTS reduction if fix is applied

Be direct and actionable. No preamble. Format as plain text with numbered sections."""

    return call_claude(prompt)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(findings, use_claude=True):
    """Generate a Markdown report from findings."""
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    outpath = REPORTS_DIR / f"cardinality_report_{ts}.md"

    total_mts = sum(f["mts_count"] for f in findings)
    critical   = [f for f in findings if f["severity"] == "CRITICAL"]
    high       = [f for f in findings if f["severity"] == "HIGH"]
    medium     = [f for f in findings if f["severity"] == "MEDIUM"]

    lines = []
    lines.append(f"# Metric Cardinality Governance Report")
    lines.append(f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Realm:** {REALM}")
    lines.append(f"**Metrics analyzed:** {len(findings)}")
    lines.append(f"**Total MTS across findings:** {total_mts:,}")
    total_cost = total_mts * MTS_COST_PER_MONTH
    lines.append(f"**Estimated monthly cost (findings only):** ~${total_cost:,.2f}/mo *(at ${MTS_COST_PER_MONTH}/MTS/mo — override with `MTS_COST_PER_MONTH` env var)*")

    # Savings summary from resolved findings
    all_resolved = db_get_resolved()
    if all_resolved:
        saved_mts   = sum(r[1] - r[3] for r in all_resolved)   # peak_mts - resolved_mts
        saved_cost  = saved_mts * MTS_COST_PER_MONTH
        lines.append(f"**Cumulative savings (resolved findings):** {saved_mts:,} MTS / ~${saved_cost:,.2f}/mo saved across {len(all_resolved)} resolved metric(s) 🎉")

    # Org limit section
    org = fetch_org_info()
    mts_limit = org.get("mtsCategoryInfo", {}).get("mtsLimitThreshold") \
             or org.get("mtsLimit") \
             or org.get("numResourcesMonitored")
    if mts_limit:
        pct_used = round(total_mts / mts_limit * 100, 1)
        lines.append(f"**Org MTS limit:** {mts_limit:,}")
        lines.append(f"**Findings as % of org limit:** {pct_used}%")

    ignored_patterns = db_get_ignored()
    lines.append(f"\n## Summary\n")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| 🔴 CRITICAL (≥{CRITICAL_MTS_COUNT:,} MTS) | {len(critical)} |")
    lines.append(f"| 🟠 HIGH (≥{HIGH_MTS_COUNT:,} MTS)     | {len(high)} |")
    lines.append(f"| 🟡 MEDIUM (≥{MEDIUM_MTS_COUNT:,} MTS)   | {len(medium)} |")
    if ignored_patterns:
        lines.append(f"| ⚪ Ignored | {len(ignored_patterns)} pattern(s) |")

    # Trend summary
    growing = [f for f in findings if f.get("trend") == "GROWING"]
    new     = [f for f in findings if f.get("trend") == "NEW"]
    if growing or new:
        lines.append(f"\n### Trend Alerts\n")
        if new:
            lines.append(f"- 🆕 **{len(new)} new metrics** appeared since last scan")
        if growing:
            lines.append(f"- 📈 **{len(growing)} metrics growing** >20% since last scan:")
            for f in growing:
                pct = int(f["growth_pct"] * 100)
                lines.append(f"  - `{f['metric']}`: {f['prev_count']:,} → {f['mts_count']:,} MTS (+{pct}%)")

    # Resolved findings section
    resolved = db_get_resolved()
    if resolved:
        lines.append(f"\n## Resolved Findings\n")
        lines.append(f"> These metrics previously exceeded severity thresholds and have since dropped >50% — fix confirmed working.\n")
        lines.append(f"| Metric | Peak MTS | Current MTS | MTS Saved | Cost Saved/Mo | Reduction | Resolved At | How |")
        lines.append(f"|--------|----------|-------------|-----------|---------------|-----------|-------------|-----|")
        current_mts_map = {f["metric"]: f["mts_count"] for f in findings}
        total_saved_mts  = 0
        total_saved_cost = 0.0
        for row in resolved:
            metric, peak_mts, peak_at, resolved_mts, resolved_at, reduction_pct, manual = row
            current      = current_mts_map.get(metric, resolved_mts)
            mts_saved    = peak_mts - current
            cost_saved   = mts_saved * MTS_COST_PER_MONTH
            total_saved_mts  += mts_saved
            total_saved_cost += cost_saved
            how          = "manual" if manual else "auto"
            resolved_date = resolved_at[:10]
            lines.append(f"| `{metric}` | {peak_mts:,} | {current:,} | {mts_saved:,} | ~${cost_saved:,.2f}/mo | -{reduction_pct}% | {resolved_date} | {how} |")
        lines.append(f"\n**Total savings: {total_saved_mts:,} MTS / ~${total_saved_cost:,.2f}/mo** across {len(resolved)} resolved metric(s)")
        lines.append("")

    lines.append(f"\n## Top Offenders\n")
    lines.append(f"| Rank | Metric | MTS Count | Est. Cost/Mo | % of Limit | Trend | Severity | Instrumentation Source | Worst Dimension | Attributed To |")
    lines.append(f"|------|--------|-----------|--------------|------------|-------|----------|-----------------------|----------------|---------------|")
    for i, f in enumerate(findings[:20], 1):
        worst       = f["worst_dim"] or "—"
        worst_count = f["worst_dim_info"]["unique_values"] if f["worst_dim_info"] else 0
        teams       = ", ".join(f["attributed_to"][:2])
        sev_icon    = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
        trend_icon  = {"GROWING": "📈", "FALLING": "📉", "NEW": "🆕", "STABLE": "➡️"}.get(f.get("trend", ""), "")
        limit_str   = f"{f['limit_pct']}%" if f.get("limit_pct") is not None else "—"
        trend_str   = f"{trend_icon} {f.get('trend','')}"
        if f.get("growth_pct") and f.get("trend") == "GROWING":
            trend_str += f" +{int(f['growth_pct']*100)}%"
        cost_str    = estimate_cost(f["mts_count"])
        lines.append(f"| {i} | `{f['metric']}` | {f['mts_count']:,} | {cost_str} | {limit_str} | {trend_str} | {sev_icon} {f['severity']} | {f['instr_source']} | `{worst}` ({worst_count:,} values) | {teams} |")

    # -----------------------------------------------------------------------
    # #10: Per-service cardinality scorecard
    # -----------------------------------------------------------------------
    service_mts = defaultdict(int)
    service_metrics = defaultdict(set)
    for f in findings:
        for svc in f.get("attribution", {}).get("services", f["attributed_to"]):
            service_mts[svc] += f["mts_count"]
            service_metrics[svc].add(f["metric"])

    if service_mts:
        lines.append(f"\n## Per-Service Cardinality Scorecard\n")
        lines.append(f"| Rank | Service | Total MTS | Est. Cost/Mo | Affected Metrics | % of Findings Total |")
        lines.append(f"|------|---------|-----------|--------------|-----------------|---------------------|")
        sorted_svcs = sorted(service_mts.items(), key=lambda x: -x[1])
        for rank, (svc, svc_total) in enumerate(sorted_svcs, 1):
            svc_pct = round(svc_total / total_mts * 100, 1) if total_mts else 0
            metric_count = len(service_metrics[svc])
            lines.append(f"| {rank} | `{svc}` | {svc_total:,} | {estimate_cost(svc_total)} | {metric_count} | {svc_pct}% |")

    # -----------------------------------------------------------------------
    # #9: Duplicate / similar metric grouping
    # -----------------------------------------------------------------------
    # Group by shared worst dimension
    dim_groups = defaultdict(list)
    for f in findings:
        if f["worst_dim"]:
            dim_groups[f["worst_dim"]].append(f)

    # Also group by metric name prefix (strip trailing _bucket/_count/_sum/_min/_max/_total)
    prefix_groups = defaultdict(list)
    for f in findings:
        stripped = re.sub(r"_(bucket|count|sum|min|max|total|created|rate)$", "", f["metric"])
        prefix_groups[stripped].append(f)

    # Only show groups with >= 2 metrics
    dim_multi = {k: v for k, v in dim_groups.items() if len(v) >= 2}
    prefix_multi = {k: v for k, v in prefix_groups.items() if len(v) >= 2}

    if dim_multi or prefix_multi:
        lines.append(f"\n## Duplicate / Similar Metric Groups\n")
        lines.append("> Metrics sharing the same high-cardinality dimension — one collector fix resolves the whole group.\n")

        # Shared-dimension groups
        if dim_multi:
            lines.append(f"### Grouped by Shared Worst Dimension\n")
            for dim, group in sorted(dim_multi.items(), key=lambda x: -sum(f["mts_count"] for f in x[1])):
                group_mts = sum(f["mts_count"] for f in group)
                dim_info = group[0]["worst_dim_info"]
                lines.append(f"#### Dimension: `{dim}` ({dim_info['unique_values']:,} unique values)")
                if dim_info.get("pattern"):
                    lines.append(f"**Anti-pattern detected:** {dim_info['pattern']}")
                lines.append(f"**Combined MTS:** {group_mts:,} | **Metrics in group:** {len(group)} | One fix resolves all {len(group)}\n")
                lines.append(f"| Metric | MTS | Severity |")
                lines.append(f"|--------|-----|----------|")
                for f in sorted(group, key=lambda x: -x["mts_count"]):
                    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
                    lines.append(f"| `{f['metric']}` | {f['mts_count']:,} | {sev_icon} {f['severity']} |")
                lines.append("")

                # Generate fix YAML for this group
                metric_names = [f["metric"] for f in group]
                fix = generate_fix_yaml(dim, metric_names, dim_info)
                lines.append(f"**Fix: OTel Collector processor (drop `{dim}`):**")
                lines.append(f"```yaml\n{fix['filter_processor']}\n```")
                lines.append(f"<details><summary>Alternative: hash instead of drop</summary>\n")
                lines.append(f"```yaml\n{fix['transform_processor']}\n```")
                lines.append(f"</details>\n")

        # Metric name family groups (same stem, different suffixes)
        if prefix_multi:
            lines.append(f"### Grouped by Metric Family (same root name)\n")
            for prefix, group in sorted(prefix_multi.items(), key=lambda x: -sum(f["mts_count"] for f in x[1])):
                group_mts = sum(f["mts_count"] for f in group)
                # Only show groups with a shared worst dim (confirms same root cause)
                worst_dims = {f["worst_dim"] for f in group if f["worst_dim"]}
                if not worst_dims:
                    continue
                lines.append(f"#### Family: `{prefix}_*`")
                lines.append(f"**Combined MTS:** {group_mts:,} | **Variants:** {len(group)} | **Shared problem dimension(s):** `{'`, `'.join(sorted(worst_dims))}`\n")
                lines.append(f"| Metric | MTS | Worst Dim |")
                lines.append(f"|--------|-----|-----------|")
                for f in sorted(group, key=lambda x: -x["mts_count"]):
                    worst = f["worst_dim"] or "—"
                    lines.append(f"| `{f['metric']}` | {f['mts_count']:,} | `{worst}` |")
                lines.append("")

                # Generate fix for the primary shared dimension (highest unique-value count)
                primary_dim = max(worst_dims, key=lambda d: next(
                    (f["worst_dim_info"]["unique_values"] for f in group if f["worst_dim"] == d), 0
                ))
                primary_dim_info = next(
                    (f["worst_dim_info"] for f in group if f["worst_dim"] == primary_dim), {}
                ) or {}
                metric_names = [f["metric"] for f in group]
                fix = generate_fix_yaml(primary_dim, metric_names, primary_dim_info)
                lines.append(f"**Fix: OTel Collector processor (drop `{primary_dim}` from all {len(group)} variants):**")
                lines.append(f"```yaml\n{fix['filter_processor']}\n```\n")

    lines.append(f"\n## Detailed Findings\n")

    for i, f in enumerate(findings, 1):
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
        lines.append(f"### {i}. `{f['metric']}` — {sev_icon} {f['severity']}")
        trend_icon = {"GROWING": "📈", "FALLING": "📉", "NEW": "🆕", "STABLE": "➡️"}.get(f.get("trend", ""), "")
        trend_str  = f.get("trend", "")
        if f.get("prev_count") is not None:
            pct = int(f["growth_pct"] * 100) if f.get("growth_pct") is not None else 0
            sign = f"+{pct}" if pct >= 0 else str(pct)
            prev_ts_short = f["prev_ts"][:10] if f.get("prev_ts") else "?"
            trend_str = f"{trend_icon} {trend_str} ({f['prev_count']:,} → {f['mts_count']:,}, {sign}% since {prev_ts_short})"
        else:
            trend_str = f"{trend_icon} {trend_str} (first scan)"

        lines.append(f"\n- **MTS count:** {f['mts_count']:,}")
        lines.append(f"- **Estimated cost:** {estimate_cost(f['mts_count'])} *(${MTS_COST_PER_MONTH}/MTS/mo)*")
        if f.get("limit_pct") is not None:
            lines.append(f"- **% of org MTS limit:** {f['limit_pct']}%")
        lines.append(f"- **Trend:** {trend_str}")
        lines.append(f"- **Metric type:** {f['type']} ({'custom' if f['custom'] else 'builtin'})")
        lines.append(f"- **Instrumentation source:** {f['instr_source']} — *{f['instr_desc']}*")

        # Rich attribution
        attr = f.get("attribution", {})
        lines.append(f"- **Services:** {', '.join(attr.get('services', f['attributed_to']))}")
        if attr.get("environments"):
            lines.append(f"- **Environments:** {', '.join(attr['environments'])}")
        if attr.get("clusters"):
            lines.append(f"- **Clusters:** {', '.join(attr['clusters'])}")
        if attr.get("namespaces"):
            lines.append(f"- **Namespaces:** {', '.join(attr['namespaces'])}")
        if attr.get("sdk"):
            lines.append(f"- **SDK:** {attr['sdk']}")

        if f["dimensions"]:
            lines.append(f"\n**High-cardinality dimensions:**\n")
            lines.append(f"| Dimension | Unique Values | Pattern | Sample Values |")
            lines.append(f"|-----------|--------------|---------|---------------|")
            for dim, info in list(f["dimensions"].items())[:8]:
                pattern = info["pattern"] or "—"
                samples = ", ".join(f"`{v}`" for v in info["sample_values"][:3])
                lines.append(f"| `{dim}` | {info['unique_values']:,} | {pattern} | {samples} |")

        if use_claude and f["severity"] in ("CRITICAL", "HIGH"):
            print(f"  Generating AI remediation for {f['metric']}...")
            remediation = generate_remediation(f)
            lines.append(f"\n**AI Remediation Recommendation:**\n")
            lines.append(f"```\n{remediation}\n```")

        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by Metric Cardinality Governance — Splunk Observability Cloud*")

    report_text = "\n".join(lines)
    outpath.write_text(report_text)
    return outpath, report_text


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def _h(text):
    """HTML-escape a string."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _sev_badge(sev):
    colors = {"CRITICAL": "#d73a49", "HIGH": "#e36209", "MEDIUM": "#b08800", "LOW": "#6a737d"}
    icons  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
    c = colors.get(sev, "#6a737d")
    icon = icons.get(sev, "")
    return f'<span class="badge" style="background:{c}">{icon} {_h(sev)}</span>'


def _trend_badge(trend, growth_pct=None):
    icons  = {"GROWING": "📈", "FALLING": "📉", "NEW": "🆕", "STABLE": "➡️"}
    colors = {"GROWING": "#d73a49", "FALLING": "#28a745", "NEW": "#0366d6", "STABLE": "#6a737d"}
    icon = icons.get(trend, "")
    c    = colors.get(trend, "#6a737d")
    label = trend
    if trend == "GROWING" and growth_pct:
        label += f" +{int(growth_pct * 100)}%"
    return f'<span class="badge" style="background:{c}">{icon} {_h(label)}</span>'


def generate_html_report(findings, use_claude=True):
    """Generate a self-contained HTML report with sortable tables and collapsible sections."""
    REPORTS_DIR.mkdir(exist_ok=True)
    ts      = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    outpath = REPORTS_DIR / f"cardinality_report_{ts}.html"

    total_mts  = sum(f["mts_count"] for f in findings)
    total_cost = total_mts * MTS_COST_PER_MONTH
    critical   = [f for f in findings if f["severity"] == "CRITICAL"]
    high       = [f for f in findings if f["severity"] == "HIGH"]
    medium     = [f for f in findings if f["severity"] == "MEDIUM"]

    org = fetch_org_info()
    mts_limit = org.get("mtsCategoryInfo", {}).get("mtsLimitThreshold") \
             or org.get("mtsLimit") or org.get("numResourcesMonitored")
    pct_used = round(total_mts / mts_limit * 100, 1) if mts_limit else None

    all_resolved    = db_get_resolved()
    ignored_patterns = db_get_ignored()
    saved_mts  = sum(r[1] - r[3] for r in all_resolved) if all_resolved else 0
    saved_cost = saved_mts * MTS_COST_PER_MONTH

    growing = [f for f in findings if f.get("trend") == "GROWING"]
    new_metrics = [f for f in findings if f.get("trend") == "NEW"]

    # ---- CSS + JS ----
    css = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f6f8fa; color: #24292e; line-height: 1.5; }
    .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
    h1 { font-size: 1.8rem; margin-bottom: 4px; }
    h2 { font-size: 1.3rem; margin: 28px 0 12px; border-bottom: 2px solid #e1e4e8; padding-bottom: 6px; }
    h3 { font-size: 1.1rem; margin: 20px 0 8px; color: #444; }
    .meta { color: #586069; font-size: 0.9rem; margin-bottom: 20px; }
    .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
    .card { background: #fff; border: 1px solid #e1e4e8; border-radius: 8px;
            padding: 16px 20px; min-width: 160px; flex: 1; }
    .card .value { font-size: 1.8rem; font-weight: 700; }
    .card .label { font-size: 0.8rem; color: #586069; text-transform: uppercase; letter-spacing: .05em; }
    .card.red   { border-top: 4px solid #d73a49; }
    .card.orange{ border-top: 4px solid #e36209; }
    .card.yellow{ border-top: 4px solid #b08800; }
    .card.green { border-top: 4px solid #28a745; }
    .card.blue  { border-top: 4px solid #0366d6; }
    table { width: 100%; border-collapse: collapse; background: #fff;
            border: 1px solid #e1e4e8; border-radius: 8px; overflow: hidden;
            font-size: 0.875rem; margin-bottom: 20px; }
    th { background: #f6f8fa; padding: 10px 12px; text-align: left;
         border-bottom: 2px solid #e1e4e8; white-space: nowrap; cursor: pointer; user-select: none; }
    th:hover { background: #eaecef; }
    th.sort-asc::after  { content: " ▲"; font-size: 0.7em; }
    th.sort-desc::after { content: " ▼"; font-size: 0.7em; }
    td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f9fafb; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600; color: #fff; white-space: nowrap; }
    .metric-name { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.82rem; }
    .dim-name    { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.82rem;
                   background: #f3f4f6; padding: 1px 5px; border-radius: 4px; }
    details { margin: 8px 0; }
    summary { cursor: pointer; font-weight: 600; color: #0366d6; padding: 6px 0; }
    summary:hover { text-decoration: underline; }
    pre { background: #1e2030; color: #cdd6f4; padding: 14px 16px; border-radius: 6px;
          font-size: 0.8rem; overflow-x: auto; white-space: pre; margin: 8px 0; }
    .alert { background: #fff8c5; border: 1px solid #f0c000; border-radius: 6px;
             padding: 10px 14px; margin-bottom: 12px; font-size: 0.9rem; }
    .alert.green { background: #dcffe4; border-color: #28a745; }
    .alert.red   { background: #ffeef0; border-color: #d73a49; }
    .group-box { background: #fff; border: 1px solid #e1e4e8; border-radius: 8px;
                 padding: 16px; margin-bottom: 16px; }
    .group-box h4 { font-size: 1rem; margin-bottom: 8px; }
    .savings-banner { background: #dcffe4; border: 1px solid #28a745; border-radius: 8px;
                      padding: 12px 16px; margin-bottom: 20px; font-size: 1rem; }
    .tab-nav { display: flex; gap: 4px; border-bottom: 2px solid #e1e4e8; margin-bottom: 20px; }
    .tab-btn { padding: 8px 16px; cursor: pointer; border: none; background: none;
               font-size: 0.9rem; color: #586069; border-bottom: 3px solid transparent;
               margin-bottom: -2px; font-weight: 500; }
    .tab-btn.active { color: #0366d6; border-bottom-color: #0366d6; }
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }
    @media (max-width: 768px) { .cards { flex-direction: column; } }
    """

    js = """
    // Tab switching
    function showTab(id) {
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        event.target.classList.add('active');
    }

    // Table sorting
    document.querySelectorAll('th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const table = th.closest('table');
            const col   = Array.from(th.parentElement.children).indexOf(th);
            const asc   = th.classList.toggle('sort-asc');
            th.classList.toggle('sort-desc', !asc);
            th.parentElement.querySelectorAll('th').forEach(t => {
                if (t !== th) { t.classList.remove('sort-asc', 'sort-desc'); }
            });
            const tbody = table.querySelector('tbody');
            const rows  = Array.from(tbody.querySelectorAll('tr'));
            rows.sort((a, b) => {
                const av = a.cells[col]?.dataset.val ?? a.cells[col]?.textContent ?? '';
                const bv = b.cells[col]?.dataset.val ?? b.cells[col]?.textContent ?? '';
                const an = parseFloat(av), bn = parseFloat(bv);
                if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
                return asc ? av.localeCompare(bv) : bv.localeCompare(av);
            });
            rows.forEach(r => tbody.appendChild(r));
        });
    });
    """

    # ---- Build HTML sections ----
    def stat_card(value, label, cls="blue"):
        return f'<div class="card {cls}"><div class="value">{_h(value)}</div><div class="label">{_h(label)}</div></div>'

    # Header cards
    cards_html = '<div class="cards">'
    cards_html += stat_card(f"{total_mts:,}", "Total MTS", "red" if critical else "orange")
    cards_html += stat_card(f"~${total_cost:,.2f}", "Est. Cost / Mo", "orange")
    cards_html += stat_card(str(len(critical)), "Critical", "red")
    cards_html += stat_card(str(len(high)), "High", "orange")
    cards_html += stat_card(str(len(medium)), "Medium", "yellow")
    if saved_mts:
        cards_html += stat_card(f"~${saved_cost:,.2f}", "Saved / Mo", "green")
    if pct_used is not None:
        cards_html += stat_card(f"{pct_used}%", "% of Org Limit", "blue")
    cards_html += "</div>"

    # Alerts
    alerts_html = ""
    if growing:
        names = ", ".join(f"<code>{_h(f['metric'])}</code>" for f in growing[:3])
        alerts_html += f'<div class="alert red">📈 <strong>{len(growing)} metric(s) growing &gt;20%</strong> since last scan: {names}{"..." if len(growing) > 3 else ""}</div>'
    if new_metrics:
        alerts_html += f'<div class="alert">🆕 <strong>{len(new_metrics)} new metric(s)</strong> appeared since last scan</div>'
    if saved_mts:
        alerts_html += f'<div class="alert green">🎉 <strong>Cumulative savings:</strong> {saved_mts:,} MTS / ~${saved_cost:,.2f}/mo across {len(all_resolved)} resolved metric(s)</div>'

    # Top offenders table
    def offenders_table(rows, limit=None):
        h = '<table><thead><tr>'
        h += '<th data-sort>Rank</th><th data-sort>Metric</th><th data-sort>MTS</th>'
        h += '<th data-sort>Est. Cost/Mo</th><th data-sort>Severity</th>'
        h += '<th data-sort>Trend</th><th data-sort>Source</th>'
        h += '<th data-sort>Worst Dimension</th><th>Services</th></tr></thead><tbody>'
        for i, f in enumerate(rows[:limit] if limit else rows, 1):
            worst = f["worst_dim"] or "—"
            worst_count = f["worst_dim_info"]["unique_values"] if f["worst_dim_info"] else 0
            services = ", ".join(f["attributed_to"][:2])
            cost = f["mts_count"] * MTS_COST_PER_MONTH
            h += f'<tr>'
            h += f'<td data-val="{i}">{i}</td>'
            h += f'<td><span class="metric-name">{_h(f["metric"])}</span></td>'
            h += f'<td data-val="{f["mts_count"]}">{f["mts_count"]:,}</td>'
            h += f'<td data-val="{cost}">~${cost:,.2f}</td>'
            h += f'<td>{_sev_badge(f["severity"])}</td>'
            h += f'<td>{_trend_badge(f.get("trend",""), f.get("growth_pct"))}</td>'
            h += f'<td>{_h(f["instr_source"])}</td>'
            h += f'<td><span class="dim-name">{_h(worst)}</span> ({worst_count:,})</td>'
            h += f'<td>{_h(services)}</td>'
            h += '</tr>'
        h += '</tbody></table>'
        return h

    # Service scorecard
    service_mts     = defaultdict(int)
    service_metrics = defaultdict(set)
    for f in findings:
        for svc in f.get("attribution", {}).get("services", f["attributed_to"]):
            service_mts[svc]     += f["mts_count"]
            service_metrics[svc].add(f["metric"])

    def scorecard_table():
        h = '<table><thead><tr><th data-sort>Rank</th><th data-sort>Service</th>'
        h += '<th data-sort>Total MTS</th><th data-sort>Est. Cost/Mo</th>'
        h += '<th data-sort>Metrics</th><th data-sort>% of Total</th></tr></thead><tbody>'
        for rank, (svc, svc_total) in enumerate(sorted(service_mts.items(), key=lambda x: -x[1]), 1):
            pct    = round(svc_total / total_mts * 100, 1) if total_mts else 0
            cost   = svc_total * MTS_COST_PER_MONTH
            n_metrics = len(service_metrics[svc])
            bar    = f'<div style="height:6px;background:#0366d6;width:{pct}%;border-radius:3px;margin-top:4px"></div>'
            h += f'<tr><td>{rank}</td><td><code>{_h(svc)}</code></td>'
            h += f'<td data-val="{svc_total}">{svc_total:,}</td>'
            h += f'<td data-val="{cost}">~${cost:,.2f}</td>'
            h += f'<td>{n_metrics}</td>'
            h += f'<td data-val="{pct}">{pct}%{bar}</td></tr>'
        h += '</tbody></table>'
        return h

    # Resolved findings table
    def resolved_table():
        if not all_resolved:
            return '<p style="color:#586069">No resolved findings yet.</p>'
        current_map = {f["metric"]: f["mts_count"] for f in findings}
        h = '<table><thead><tr><th>Metric</th><th data-sort>Peak MTS</th>'
        h += '<th data-sort>Current MTS</th><th data-sort>MTS Saved</th>'
        h += '<th data-sort>Cost Saved/Mo</th><th data-sort>Reduction</th>'
        h += '<th>Resolved At</th><th>How</th></tr></thead><tbody>'
        for row in all_resolved:
            metric, peak_mts, peak_at, resolved_mts, resolved_at, reduction_pct, manual = row
            current   = current_map.get(metric, resolved_mts)
            mts_saved = peak_mts - current
            cost_saved = mts_saved * MTS_COST_PER_MONTH
            how = "manual" if manual else "auto"
            h += f'<tr><td><span class="metric-name">{_h(metric)}</span></td>'
            h += f'<td data-val="{peak_mts}">{peak_mts:,}</td>'
            h += f'<td data-val="{current}">{current:,}</td>'
            h += f'<td data-val="{mts_saved}">{mts_saved:,}</td>'
            h += f'<td data-val="{cost_saved}">~${cost_saved:,.2f}</td>'
            h += f'<td data-val="{reduction_pct}">-{reduction_pct}%</td>'
            h += f'<td>{_h(resolved_at[:10])}</td><td>{_h(how)}</td></tr>'
        h += '</tbody></table>'
        return h

    # Duplicate groups
    dim_groups    = defaultdict(list)
    prefix_groups = defaultdict(list)
    for f in findings:
        if f["worst_dim"]:
            dim_groups[f["worst_dim"]].append(f)
        stripped = re.sub(r"_(bucket|count|sum|min|max|total|created|rate)$", "", f["metric"])
        prefix_groups[stripped].append(f)
    dim_multi    = {k: v for k, v in dim_groups.items() if len(v) >= 2}
    prefix_multi = {k: v for k, v in prefix_groups.items() if len(v) >= 2}

    def groups_html():
        h = ""
        if dim_multi:
            h += "<h3>Grouped by Shared Worst Dimension</h3>"
            for dim, group in sorted(dim_multi.items(), key=lambda x: -sum(f["mts_count"] for f in x[1])):
                group_mts = sum(f["mts_count"] for f in group)
                dim_info  = group[0]["worst_dim_info"]
                fix       = generate_fix_yaml(dim, [f["metric"] for f in group], dim_info)
                pat_badge = f' <span class="badge" style="background:#d73a49">{_h(dim_info["pattern"])}</span>' if dim_info.get("pattern") else ""
                h += f'<div class="group-box">'
                h += f'<h4><span class="dim-name">{_h(dim)}</span> &mdash; {dim_info["unique_values"]:,} unique values{pat_badge}</h4>'
                h += f'<p style="margin-bottom:8px"><strong>{group_mts:,} combined MTS</strong> &middot; {len(group)} metrics &middot; <em>one fix resolves all {len(group)}</em></p>'
                h += '<table><thead><tr><th>Metric</th><th data-sort>MTS</th><th>Severity</th></tr></thead><tbody>'
                for f in sorted(group, key=lambda x: -x["mts_count"]):
                    h += f'<tr><td><span class="metric-name">{_h(f["metric"])}</span></td>'
                    h += f'<td data-val="{f["mts_count"]}">{f["mts_count"]:,}</td>'
                    h += f'<td>{_sev_badge(f["severity"])}</td></tr>'
                h += '</tbody></table>'
                h += f'<details><summary>Fix: drop <code>{_h(dim)}</code> (OTel Collector YAML)</summary>'
                h += f'<pre>{_h(fix["filter_processor"])}</pre>'
                h += f'<details><summary>Alternative: hash instead of drop</summary>'
                h += f'<pre>{_h(fix["transform_processor"])}</pre></details>'
                h += '</details></div>'
        return h

    # Detailed findings
    def detailed_html():
        h = ""
        for i, f in enumerate(findings, 1):
            attr = f.get("attribution", {})
            sev  = f["severity"]
            trend_str = f.get("trend", "")
            if f.get("prev_count") is not None and f.get("growth_pct") is not None:
                pct = int(f["growth_pct"] * 100)
                trend_str += f" ({f['prev_count']:,} → {f['mts_count']:,}, {'+' if pct >= 0 else ''}{pct}%)"
            cost = f["mts_count"] * MTS_COST_PER_MONTH

            h += f'<details><summary>{i}. <span class="metric-name">{_h(f["metric"])}</span> &nbsp; {_sev_badge(sev)} &nbsp; {f["mts_count"]:,} MTS &nbsp; ~${cost:,.2f}/mo</summary>'
            h += '<div style="padding:12px 0">'
            h += f'<p><strong>Instrumentation:</strong> {_h(f["instr_source"])} &mdash; <em>{_h(f["instr_desc"])}</em></p>'
            h += f'<p><strong>Trend:</strong> {_trend_badge(f.get("trend",""), f.get("growth_pct"))} {_h(trend_str)}</p>'
            h += f'<p><strong>Services:</strong> {_h(", ".join(attr.get("services", f["attributed_to"])))}</p>'
            if attr.get("environments"):
                h += f'<p><strong>Environments:</strong> {_h(", ".join(attr["environments"]))}</p>'
            if attr.get("clusters"):
                h += f'<p><strong>Clusters:</strong> {_h(", ".join(attr["clusters"]))}</p>'
            if attr.get("sdk"):
                h += f'<p><strong>SDK:</strong> {_h(attr["sdk"])}</p>'

            if f["dimensions"]:
                h += '<table style="margin-top:10px"><thead><tr><th>Dimension</th><th data-sort>Unique Values</th><th>Pattern</th><th>Sample Values</th></tr></thead><tbody>'
                for dim, info in list(f["dimensions"].items())[:8]:
                    pattern = info["pattern"] or "—"
                    samples = ", ".join(f"<code>{_h(v)}</code>" for v in info["sample_values"][:3])
                    h += f'<tr><td><span class="dim-name">{_h(dim)}</span></td>'
                    h += f'<td data-val="{info["unique_values"]}">{info["unique_values"]:,}</td>'
                    h += f'<td>{_h(pattern)}</td><td>{samples}</td></tr>'
                h += '</tbody></table>'

            if use_claude and sev in ("CRITICAL", "HIGH"):
                print(f"  Generating AI remediation for {f['metric']}...")
                remediation = generate_remediation(f)
                h += f'<details style="margin-top:10px"><summary>AI Remediation</summary><pre>{_h(remediation)}</pre></details>'

            h += '</div></details>'
        return h

    # Ignored patterns
    def ignored_html():
        if not ignored_patterns:
            return '<p style="color:#586069">No patterns in ignore list.</p>'
        h = '<table><thead><tr><th>Pattern</th><th>Reason</th><th>Since</th></tr></thead><tbody>'
        for pattern, reason, ignored_at in ignored_patterns:
            h += f'<tr><td><code>{_h(pattern)}</code></td><td>{_h(reason or "—")}</td><td>{_h(ignored_at[:10])}</td></tr>'
        h += '</tbody></table>'
        return h

    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    limit_line = f" &middot; Org limit: {mts_limit:,} ({pct_used}% used)" if mts_limit else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cardinality Governance Report — {_h(REALM)}</title>
<style>{css}</style>
</head>
<body>
<div class="container">
  <h1>Metric Cardinality Governance</h1>
  <div class="meta">Generated {_h(gen_time)} &middot; Realm: <strong>{_h(REALM)}</strong> &middot; {len(findings)} metrics analyzed{limit_line}</div>

  {cards_html}
  {alerts_html}

  <div class="tab-nav">
    <button class="tab-btn active" onclick="showTab('tab-offenders')">Top Offenders</button>
    <button class="tab-btn" onclick="showTab('tab-scorecard')">Service Scorecard</button>
    <button class="tab-btn" onclick="showTab('tab-groups')">Duplicate Groups</button>
    <button class="tab-btn" onclick="showTab('tab-resolved')">Resolved ({len(all_resolved)})</button>
    <button class="tab-btn" onclick="showTab('tab-details')">Detailed Findings</button>
    <button class="tab-btn" onclick="showTab('tab-ignored')">Ignored ({len(ignored_patterns)})</button>
  </div>

  <div id="tab-offenders" class="tab-pane active">
    <h2>Top Offenders</h2>
    {offenders_table(findings, limit=50)}
  </div>

  <div id="tab-scorecard" class="tab-pane">
    <h2>Per-Service Cardinality Scorecard</h2>
    {scorecard_table()}
  </div>

  <div id="tab-groups" class="tab-pane">
    <h2>Duplicate / Similar Metric Groups</h2>
    <p style="margin-bottom:16px;color:#586069">Metrics sharing the same high-cardinality dimension — one collector fix resolves the whole group.</p>
    {groups_html()}
  </div>

  <div id="tab-resolved" class="tab-pane">
    <h2>Resolved Findings</h2>
    {resolved_table()}
  </div>

  <div id="tab-details" class="tab-pane">
    <h2>Detailed Findings</h2>
    <p style="margin-bottom:12px;color:#586069">Click a metric to expand dimension analysis and AI remediation.</p>
    {detailed_html()}
  </div>

  <div id="tab-ignored" class="tab-pane">
    <h2>Ignored Patterns</h2>
    {ignored_html()}
  </div>

  <p style="margin-top:32px;color:#586069;font-size:0.8rem">Generated by Metric Cardinality Governance &mdash; Splunk Observability Cloud</p>
</div>
<script>{js}</script>
</body>
</html>"""

    outpath.write_text(html)
    return outpath


# ---------------------------------------------------------------------------
# Watch mode
# ---------------------------------------------------------------------------

def watch_mode(interval=300, threshold=HIGH_MTS_COUNT):
    """Continuously poll for new cardinality explosions and emit events."""
    print(f"\nWatch mode (interval={interval}s, threshold={threshold:,} MTS)\n")
    known = {}

    while True:
        findings = scan_org(top_n=100, verbose=False)
        for f in findings:
            key = f["metric"]
            prev_count = known.get(key, 0)
            curr_count = f["mts_count"]

            # New explosion or >50% growth
            if prev_count == 0 and curr_count >= threshold:
                print(f"  [NEW EXPLOSION] {key}: {curr_count:,} MTS ({f['severity']})")
                ingest_event(
                    "cardinality.explosion.detected",
                    {"metric": key, "realm": REALM},
                    {
                        "mts_count":     curr_count,
                        "severity":      f["severity"],
                        "worst_dim":     f["worst_dim"] or "",
                        "attributed_to": ",".join(f["attributed_to"]),
                    }
                )
            elif prev_count > 0 and curr_count > prev_count * 1.5:
                pct = int((curr_count - prev_count) / prev_count * 100)
                print(f"  [GROWTH +{pct}%] {key}: {prev_count:,} → {curr_count:,} MTS")
                ingest_event(
                    "cardinality.explosion.growing",
                    {"metric": key, "realm": REALM},
                    {
                        "mts_count":      curr_count,
                        "prev_mts_count": prev_count,
                        "growth_pct":     pct,
                        "severity":       f["severity"],
                    }
                )

            known[key] = curr_count

        print(f"  [{datetime.now().strftime('%H:%M:%S')}] Scan complete. {len(findings)} findings. Sleeping {interval}s...")
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Rollup suggestion
# ---------------------------------------------------------------------------

def show_history(limit=30):
    """Print a table of past scan summaries."""
    rows = db_get_scan_history(limit)
    if not rows:
        print("No scan history found. Run 'scan' or 'report' first.")
        return

    print(f"\nScan history (realm={REALM}, last {len(rows)} scans)\n")
    print(f"{'Date':<22} {'Metrics':>8} {'Total MTS':>10} {'Est Cost/Mo':>12} {'🔴':>5} {'🟠':>5} {'🟡':>5} {'Ignored':>8}")
    print("-" * 85)

    for row in reversed(rows):   # oldest first for trend readability
        scanned_at, total_metrics, total_mts, critical, high, medium, ignored = row
        cost = total_mts * MTS_COST_PER_MONTH
        date_str = scanned_at[:16].replace("T", " ")
        print(f"{date_str:<22} {total_metrics:>8,} {total_mts:>10,} {f'~${cost:,.2f}':>12} {critical:>5} {high:>5} {medium:>5} {ignored:>8}")

    # Trend arrow: compare first vs last
    if len(rows) >= 2:
        latest, oldest = rows[0], rows[-1]
        mts_change = latest[2] - oldest[2]
        pct = round(mts_change / oldest[2] * 100, 1) if oldest[2] else 0
        direction = "📈 UP" if mts_change > 0 else "📉 DOWN" if mts_change < 0 else "➡️ FLAT"
        cost_change = mts_change * MTS_COST_PER_MONTH
        print(f"\nTrend over {len(rows)} scans: {direction} {abs(pct)}%  ({'+' if mts_change >= 0 else ''}{mts_change:,} MTS  /  {'+'if cost_change >= 0 else ''}~${cost_change:,.2f}/mo)")


def drilldown_dimension(dimension_name, top_n=50):
    """
    Show every metric in the org that carries a given dimension,
    ranked by unique value count — full blast radius before applying a fix.
    """
    print(f"\nDimension drill-down: `{dimension_name}` (realm={REALM})\n")
    print("  Fetching metric catalog...")
    metrics = fetch_metrics()
    print(f"  Scanning {len(metrics)} metrics for dimension `{dimension_name}`...\n")

    hits = []
    for i, metric in enumerate(metrics):
        name = metric.get("name", "")
        mts_list = fetch_mts_for_metric(name, limit=500)
        if not mts_list:
            continue

        # Check if this dimension exists in the sampled MTS
        values = set()
        for mts in mts_list:
            v = mts.get("dimensions", {}).get(dimension_name)
            if v is not None:
                values.add(str(v))

        if not values:
            continue

        pattern = None
        for v in list(values)[:5]:
            p = detect_cardinality_pattern(v)
            if p:
                pattern = p
                break

        instr_source, _ = infer_instrumentation_source(name, mts_list)
        mts_count = len(mts_list)
        attribution = attribute_detail(mts_list)

        hits.append({
            "metric":       name,
            "mts_count":    mts_count,
            "unique_values": len(values),
            "sample_values": sorted(values)[:5],
            "pattern":      pattern,
            "instr_source": instr_source,
            "services":     attribution["services"],
        })

    if not hits:
        print(f"  No metrics found carrying dimension `{dimension_name}`.")
        return

    hits.sort(key=lambda x: -x["unique_values"])
    total_mts     = sum(h["mts_count"] for h in hits)
    total_cost    = total_mts * MTS_COST_PER_MONTH
    max_unique    = max(h["unique_values"] for h in hits)

    print(f"  Found {len(hits)} metric(s) carrying `{dimension_name}`")
    print(f"  Combined MTS: {total_mts:,}  |  Est. cost: ~${total_cost:,.2f}/mo")
    print(f"  Max unique values seen: {max_unique:,}")
    if hits[0].get("pattern"):
        print(f"  Anti-pattern detected: {hits[0]['pattern']}")
    print()

    # Print ranked table
    print(f"{'Rank':<5} {'Metric':<50} {'MTS':>7} {'Unique Values':>13} {'Pattern':<18} {'Source':<25} Services")
    print("-" * 140)
    for i, h in enumerate(hits[:top_n], 1):
        pattern_str  = h["pattern"] or "—"
        services_str = ", ".join(h["services"][:2])
        print(f"{i:<5} {h['metric']:<50} {h['mts_count']:>7,} {h['unique_values']:>13,} {pattern_str:<18} {h['instr_source']:<25} {services_str}")

    print()
    # Generate the fix YAML for this dimension across all affected metrics
    all_metric_names = [h["metric"] for h in hits]
    dim_info = {"unique_values": max_unique, "pattern": hits[0].get("pattern")}
    fix = generate_fix_yaml(dimension_name, all_metric_names, dim_info)

    print("=" * 70)
    print(f"FIX: Drop `{dimension_name}` from all {len(hits)} affected metrics")
    print("=" * 70)
    print(fix["filter_processor"])
    print()
    print("--- Alternative: hash instead of drop ---")
    print(fix["transform_processor"])


def suggest_rollup(metric_name):
    """Generate a SignalFlow rollup suggestion for a specific metric."""
    mts_list = fetch_mts_for_metric(metric_name, limit=10000)
    if not mts_list:
        print(f"No MTS found for metric '{metric_name}'")
        return

    mts_count = len(mts_list)
    dim_analysis = analyze_dimensions(mts_list)

    print(f"\nMetric: {metric_name}")
    print(f"MTS count: {mts_count:,}")
    print(f"\nDimensions:")
    for dim, info in dim_analysis.items():
        pattern = f" [{info['pattern']}]" if info["pattern"] else ""
        print(f"  {dim}: {info['unique_values']:,} unique values{pattern}")

    print(f"\nGenerating rollup recommendations...\n")

    # Build list of safe (low-cardinality) dimensions to keep
    safe_dims = [d for d, info in dim_analysis.items() if info["unique_values"] <= 50]
    noisy_dims = [d for d, info in dim_analysis.items() if info["unique_values"] > 50]

    prompt = f"""You are a SignalFlow and Splunk Observability Cloud expert.

Metric: {metric_name}
Total MTS: {mts_count:,}

All dimensions with cardinality:
{json.dumps(dim_analysis, indent=2, default=str)}

Safe dimensions to keep (low cardinality): {safe_dims}
Noisy dimensions to drop/aggregate (high cardinality): {noisy_dims}

Generate:
1. The recommended SignalFlow rollup (using data() with sum(by=[...]) keeping only safe dims)
2. An OTel Collector processor config snippet to drop the noisy dimensions at collection time
3. A brief explanation of the expected MTS reduction

Return ONLY the content, no preamble."""

    result = call_claude(prompt)
    print(result)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Metric Cardinality Governance for Splunk Observability Cloud")
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan org for cardinality issues")
    p_scan.add_argument("--top", type=int, default=20, help="Show top N metrics (default: 20)")
    p_scan.add_argument("--verbose", action="store_true", help="Show all metrics including LOW severity")

    # report
    p_report = sub.add_parser("report", help="Generate full Markdown or HTML report with AI remediation")
    p_report.add_argument("--top", type=int, default=50, help="Analyze top N metrics (default: 50)")
    p_report.add_argument("--no-ai", action="store_true", help="Skip AI remediation (faster)")
    p_report.add_argument("--format", choices=["md", "html", "both"], default="md",
                          help="Output format: md (default), html, or both")

    # watch
    p_watch = sub.add_parser("watch", help="Continuously monitor for cardinality explosions")
    p_watch.add_argument("--interval", type=int, default=300, help="Scan interval in seconds (default: 300)")
    p_watch.add_argument("--threshold", type=int, default=HIGH_MTS_COUNT, help="MTS threshold for alerts")

    # rollup
    p_rollup = sub.add_parser("rollup", help="Generate rollup suggestions for a specific metric")
    p_rollup.add_argument("--metric", required=True, help="Metric name to analyze")

    # resolve
    p_resolve = sub.add_parser("resolve", help="Manually mark a metric as remediated")
    p_resolve.add_argument("--metric", required=True, help="Metric name to mark resolved")
    p_resolve.add_argument("--note", default="", help="Optional note (e.g. 'applied delete_key fix in collector v1.2')")

    # drilldown
    p_drill = sub.add_parser("drilldown", help="Show all metrics carrying a given dimension — full blast radius before applying a fix")
    p_drill.add_argument("--dimension", required=True, help="Dimension name to drill down on (e.g. server.address)")
    p_drill.add_argument("--top", type=int, default=50, help="Show top N metrics (default: 50)")

    # ignore / unignore
    p_ignore = sub.add_parser("ignore", help="Exclude a metric or glob pattern from future reports")
    p_ignore.add_argument("pattern", help="Metric name or glob pattern (e.g. 'sf.org.*', 'otelcol_*')")
    p_ignore.add_argument("--reason", default="", help="Why this metric is being ignored")

    p_unignore = sub.add_parser("unignore", help="Remove a metric or pattern from the ignore list")
    p_unignore.add_argument("pattern", help="Pattern to remove")

    sub.add_parser("ignored", help="List all currently ignored patterns")

    # history
    p_history = sub.add_parser("history", help="Show scan history — total MTS and cost trend over time")
    p_history.add_argument("--limit", type=int, default=30, help="Number of past scans to show (default: 30)")

    args = parser.parse_args()

    if not TOKEN:
        print("Error: SPLUNK_ACCESS_TOKEN not set")
        sys.exit(1)

    if args.command == "scan":
        findings = scan_org(top_n=args.top, verbose=args.verbose)
        if not findings:
            print("No cardinality issues found.")
            return

        print(f"\n{'Rank':<5} {'Metric':<45} {'MTS':>8} {'Trend':<12} {'Severity':<12} {'Source':<28} {'Worst Dimension'}")
        print("-" * 140)
        for i, f in enumerate(findings, 1):
            sev_icon   = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "⚪")
            trend_icon = {"GROWING": "📈", "FALLING": "📉", "NEW": "🆕", "STABLE": "➡️"}.get(f.get("trend",""), "")
            trend_str  = f"{trend_icon}{f.get('trend','')}"
            if f.get("growth_pct") and f.get("trend") == "GROWING":
                trend_str += f"(+{int(f['growth_pct']*100)}%)"
            worst = f"{f['worst_dim']} ({f['worst_dim_info']['unique_values']:,})" if f["worst_dim"] else "—"
            print(f"{i:<5} {f['metric']:<45} {f['mts_count']:>8,} {trend_str:<14} {sev_icon+f['severity']:<14} {f['instr_source']:<28} {worst}")

    elif args.command == "report":
        findings = scan_org(top_n=args.top)
        if not findings:
            print("No cardinality issues found.")
            return
        print(f"\nGenerating report for {len(findings)} findings...")
        fmt = args.format
        if fmt in ("md", "both"):
            outpath, _ = generate_report(findings, use_claude=not args.no_ai)
            print(f"Markdown report: {outpath}")
        if fmt in ("html", "both"):
            html_path = generate_html_report(findings, use_claude=not args.no_ai and fmt == "html")
            print(f"HTML report:     {html_path}")
            try:
                import subprocess
                subprocess.Popen(["open", str(html_path)])
            except Exception:
                pass

    elif args.command == "watch":
        watch_mode(interval=args.interval, threshold=args.threshold)

    elif args.command == "rollup":
        suggest_rollup(args.metric)

    elif args.command == "drilldown":
        drilldown_dimension(args.dimension, top_n=args.top)

    elif args.command == "ignore":
        db_ignore(args.pattern, reason=args.reason)
        print(f"Ignored: '{args.pattern}'" + (f" — {args.reason}" if args.reason else ""))
        print("This pattern will be excluded from all future scans and reports.")

    elif args.command == "unignore":
        db_unignore(args.pattern)
        print(f"Removed '{args.pattern}' from ignore list.")

    elif args.command == "ignored":
        rows = db_get_ignored()
        if not rows:
            print("No patterns in ignore list.")
        else:
            print(f"\nIgnored patterns (realm={REALM}):\n")
            print(f"{'Pattern':<45} {'Reason':<40} {'Since'}")
            print("-" * 100)
            for pattern, reason, ignored_at in rows:
                print(f"{pattern:<45} {reason or '—':<40} {ignored_at[:10]}")

    elif args.command == "history":
        show_history(limit=args.limit)

    elif args.command == "resolve":
        mts_list = fetch_mts_for_metric(args.metric, limit=100)
        current_mts = len(mts_list)
        peak_mts, peak_at = db_get_peak(args.metric)
        if peak_mts is None:
            print(f"No scan history found for '{args.metric}'. Run 'scan' first.")
            sys.exit(1)
        if db_is_resolved(args.metric):
            print(f"'{args.metric}' is already marked resolved.")
            sys.exit(0)
        reduction_pct = db_mark_resolved(args.metric, peak_mts, peak_at, current_mts, manual=True)
        print(f"Marked '{args.metric}' as resolved.")
        print(f"  Peak MTS:    {peak_mts:,} (at {peak_at[:10]})")
        print(f"  Current MTS: {current_mts:,}")
        print(f"  Reduction:   -{reduction_pct}%")
        if args.note:
            print(f"  Note: {args.note}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
