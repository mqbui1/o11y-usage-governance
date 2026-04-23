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
ANOMALY_RATIO        = float(os.environ.get("ANOMALY_RATIO", "2.0"))  # flag if current MTS > N× 7-day avg
ANOMALY_MIN_SAMPLES  = int(os.environ.get("ANOMALY_MIN_SAMPLES", "3"))  # need at least this many history points

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


def db_get_7day_avg(metric_name, days=7):
    """
    Return the average MTS count for a metric over the last N days of scan history.
    Returns (avg, num_samples) or (None, 0) if insufficient history.
    """
    if not STATE_DB.exists():
        return None, 0
    conn = db_connect()
    rows = conn.execute(
        """SELECT mts_count FROM scans
           WHERE realm=? AND metric=?
             AND scanned_at >= datetime('now', ?)
           ORDER BY scanned_at DESC""",
        (REALM, metric_name, f"-{days} days")
    ).fetchall()
    conn.close()
    if not rows:
        return None, 0
    values = [r[0] for r in rows]
    return sum(values) / len(values), len(values)


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

        # Anomaly detection: flag metrics growing faster than their own 7-day baseline
        baseline_avg, baseline_samples = db_get_7day_avg(name)
        anomaly = False
        baseline_ratio = None
        if baseline_avg and baseline_avg > 0 and baseline_samples >= ANOMALY_MIN_SAMPLES:
            baseline_ratio = round(mts_count / baseline_avg, 2)
            if baseline_ratio >= ANOMALY_RATIO:
                anomaly = True

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
            "anomaly":        anomaly,
            "baseline_ratio": baseline_ratio,
            "baseline_samples": baseline_samples if baseline_avg else 0,
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
    """Generate a self-contained HTML report matching the o11y-adoption design."""
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

    growing     = [f for f in findings if f.get("trend") == "GROWING"]
    new_metrics = [f for f in findings if f.get("trend") == "NEW"]
    anomalies   = [f for f in findings if f.get("anomaly")]

    # Health grade: penalise weighted by log10(mts_count) so large explosions hurt more
    import math as _math
    def _penalty(finding_list, flat):
        return sum(flat * max(1.0, _math.log10(max(1, f["mts_count"]))) for f in finding_list)
    _score = 100
    _score -= _penalty(critical, 6)
    _score -= _penalty(high,     3)
    _score -= _penalty(medium,   1)
    _score -= _penalty(growing,  2)
    health_score = max(0, min(100, round(_score)))
    grade        = "A" if health_score >= 80 else "B" if health_score >= 65 else "C" if health_score >= 50 else "D" if health_score >= 35 else "F"
    grade_color  = {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}[grade]

    # Recommended actions
    def _recommended_actions():
        actions = []
        for f in critical[:5]:
            cost = f["mts_count"] * MTS_COST_PER_MONTH
            actions.append({"priority": "critical", "category": "Cardinality",
                            "action": f"Fix CRITICAL metric: {f['metric']}",
                            "detail": f"{f['mts_count']:,} MTS · ~${cost:,.2f}/mo · worst dim: {f['worst_dim'] or '?'}"})
        if growing:
            actions.append({"priority": "high", "category": "Trend",
                            "action": f"Investigate {len(growing)} metric(s) growing >20%",
                            "detail": ", ".join(f["metric"] for f in growing[:3])})
        if anomalies:
            actions.append({"priority": "high", "category": "Anomaly",
                            "action": f"{len(anomalies)} metric(s) growing faster than 7-day baseline",
                            "detail": ", ".join(f["metric"] for f in anomalies[:3])})
        for f in high[:3]:
            actions.append({"priority": "high", "category": "Cardinality",
                            "action": f"Remediate HIGH metric: {f['metric']}",
                            "detail": f"{f['mts_count']:,} MTS · worst dim: {f['worst_dim'] or '?'}"})
        if pct_used and pct_used > 80:
            actions.append({"priority": "critical", "category": "Capacity",
                            "action": f"Org MTS at {pct_used}% of limit — immediate action required",
                            "detail": f"{total_mts:,} / {mts_limit:,} MTS"})
        if medium:
            actions.append({"priority": "medium", "category": "Cardinality",
                            "action": f"Plan remediation for {len(medium)} MEDIUM metric(s)",
                            "detail": "Address in next sprint"})
        return actions

    actions = _recommended_actions()

    # Service scorecard (computed early, used in multiple sections)
    service_mts     = defaultdict(int)
    service_metrics = defaultdict(set)
    for f in findings:
        for svc in f.get("attribution", {}).get("services", f["attributed_to"]):
            service_mts[svc]     += f["mts_count"]
            service_metrics[svc].add(f["metric"])

    # Scan history for trend section
    scan_history = db_get_scan_history(limit=10)

    # ---- CSS ----
    css = """
    :root {
      --bg: #f1f5f9; --surface: #fff; --border: #e2e8f0; --text: #1e293b;
      --muted: #64748b; --subtle: #94a3b8; --hover: #f8fafc; --input-bg: #fff;
    }
    [data-theme="dark"] {
      --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #f1f5f9;
      --muted: #94a3b8; --subtle: #64748b; --hover: #273549; --input-bg: #1e293b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: var(--bg); color: var(--text); font-size: 14px; transition: background .2s, color .2s; }
    .layout { display: flex; gap: 0; min-height: 100vh; }
    .sidebar {
      width: 220px; min-width: 220px; background: var(--surface); border-right: 1px solid var(--border);
      padding: 16px 12px; position: sticky; top: 0; height: 100vh; overflow-y: auto;
      font-size: 12px; flex-shrink: 0;
    }
    .sidebar h3 { font-size: 10px; font-weight: 700; text-transform: uppercase;
                  letter-spacing: .08em; color: var(--subtle); margin: 12px 0 4px; }
    .sidebar a { display: block; padding: 4px 8px; border-radius: 6px; color: var(--muted);
                 text-decoration: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .sidebar a:hover { background: var(--hover); color: var(--text); }
    .page { flex: 1; max-width: 1100px; padding: 24px; padding-top: 52px; }
    header { background: linear-gradient(135deg,#0f172a,#1e3a5f);
             color: #fff; border-radius: 12px; padding: 24px 28px; margin-bottom: 20px;
             display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
    header h1 { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
    header p  { font-size: 12px; color: #94a3b8; }
    .header-controls { display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
    .card { background: var(--surface); border-radius: 12px; border: 1px solid var(--border);
            padding: 20px 24px; margin-bottom: 16px; }
    .card summary { outline: none; list-style: none; }
    .card summary::-webkit-details-marker { display: none; }
    .card[open] .toggle-icon::before { content: "▲"; }
    .card:not([open]) .toggle-icon::before { content: "▼"; }
    .card-title { font-size: 13px; font-weight: 700; text-transform: uppercase;
                  letter-spacing: .05em; color: var(--muted); }
    .card h2 { font-size: 13px; font-weight: 700; text-transform: uppercase;
               letter-spacing: .05em; color: var(--muted); margin-bottom: 14px;
               padding-bottom: 8px; border-bottom: 1px solid var(--border); }
    .stat-grid { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 4px; }
    .stat { background: var(--hover); border: 1px solid var(--border); border-radius: 8px;
            padding: 12px 18px; text-align: center; min-width: 110px; }
    .stat .val { font-size: 26px; font-weight: 800; color: var(--text); }
    .stat .lbl { font-size: 10px; color: var(--subtle); margin-top: 2px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: var(--hover); color: var(--muted); font-size: 10px; font-weight: 600;
         text-transform: uppercase; letter-spacing: .05em;
         padding: 7px 10px; text-align: left; border-bottom: 2px solid var(--border);
         cursor: pointer; user-select: none; white-space: nowrap; }
    th:hover { background: var(--border); }
    th.sort-asc::after  { content: " ▲"; font-size: 0.7em; }
    th.sort-desc::after { content: " ▼"; font-size: 0.7em; }
    td { padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; color: var(--text); }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: var(--hover); }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600; color: #fff; white-space: nowrap; }
    .metric-name { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.82rem; white-space: nowrap; }
    .dim-name    { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.82rem;
                   background: var(--hover); padding: 1px 5px; border-radius: 4px; border: 1px solid var(--border); }
    details.finding { margin: 6px 0; }
    details.finding > summary { cursor: pointer; font-weight: 600; color: #3b82f6; padding: 6px 0; }
    details.finding > summary:hover { text-decoration: underline; }
    pre { background: #1e2030; color: #cdd6f4; padding: 14px 16px; border-radius: 6px;
          font-size: 0.8rem; overflow-x: auto; white-space: pre; margin: 8px 0; }
    .group-box { background: var(--hover); border: 1px solid var(--border); border-radius: 8px;
                 padding: 16px; margin-bottom: 16px; }
    .group-box h4 { font-size: 13px; margin-bottom: 8px; }
    details[id], .card[id] { scroll-margin-top: 52px; }
    .col-extra { display: none; }
    .show-extra .col-extra { display: table-cell; }
    .btn-expand-cols {
      font-size: 11px; padding: 3px 10px; border-radius: 6px; border: 1px solid var(--border);
      background: var(--hover); color: var(--muted); cursor: pointer; margin-bottom: 8px;
    }
    .btn-expand-cols:hover { background: var(--border); }
    .copy-yaml-btn {
      float: right; font-size: 10px; padding: 2px 8px; border-radius: 5px; border: 1px solid var(--border);
      background: var(--hover); color: var(--muted); cursor: pointer; margin-left: 8px;
    }
    .copy-yaml-btn:hover { background: var(--border); color: var(--text); }
    .savings-bar { height: 8px; border-radius: 4px; background: #22c55e; display: inline-block; min-width: 2px; }
    #search-box {
      width: 100%; padding: 6px 10px; border: 1px solid var(--border); border-radius: 8px;
      font-size: 12px; background: var(--input-bg); color: var(--text); margin-bottom: 8px;
    }
    .search-hide { display: none !important; }
    .btn-toggle {
      background: rgba(255,255,255,.15); border: 1px solid rgba(255,255,255,.3);
      color: #fff; border-radius: 8px; padding: 5px 12px; font-size: 12px;
      cursor: pointer; white-space: nowrap;
    }
    .btn-toggle:hover { background: rgba(255,255,255,.25); }
    #sticky-bar {
      position: fixed; top: 0; left: 0; right: 0; z-index: 999;
      background: #0f172a; color: #fff; padding: 6px 20px;
      display: flex; align-items: center; gap: 20px; font-size: 12px;
      box-shadow: 0 2px 8px rgba(0,0,0,.3); transition: transform .2s;
    }
    #sticky-bar.hidden { transform: translateY(-100%); }
    #sticky-bar .sb-grade { font-size:18px; font-weight:900; }
    #sticky-bar .sb-sep   { color: #475569; }
    #sticky-bar .sb-risk  { background:#ef4444; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
    #sticky-bar .sb-warn  { background:#f97316; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
    #sticky-bar .sb-close { margin-left:auto; cursor:pointer; color:#94a3b8; font-size:16px; line-height:1; }
    @media (max-width: 768px) { .sidebar { display: none; } .layout { display: block; } #sticky-bar { display: none; } }
    @media print {
      body { background: #fff; color: #000; font-size: 11px; }
      .sidebar, .header-controls, #search-box, #sticky-bar { display: none !important; }
      .layout { display: block; }
      .page { max-width: 100%; padding: 0; }
      .card { break-inside: avoid; border: 1px solid #ccc; margin-bottom: 10px; box-shadow: none; }
      header { background: #0f172a; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      details.card { display: block; }
      details.card summary { display: none; }
      th { background: #eee; }
      tr:hover td { background: transparent; }
    }
    """

    # ---- JS ----
    js = """
    function toggleDark() {
      const html = document.documentElement;
      html.dataset.theme = html.dataset.theme === 'dark' ? 'light' : 'dark';
    }
    function toggleExtraCols(btn, tableId) {
      const tbl = document.getElementById(tableId);
      if (!tbl) return;
      const showing = tbl.classList.toggle('show-extra');
      btn.textContent = showing ? 'Hide columns ▲' : 'Show more columns ▼';
    }
    function copyYaml(btn, text) {
      navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = orig, 1500);
      }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text; document.body.appendChild(ta);
        ta.select(); document.execCommand('copy');
        document.body.removeChild(ta);
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = orig, 1500);
      });
    }
    function filterReport(q) {
      q = q.toLowerCase();
      document.querySelectorAll('.card[id]').forEach(el => {
        el.classList.toggle('search-hide', q && !el.textContent.toLowerCase().includes(q));
      });
    }
    // Build sidebar nav from card anchors
    document.addEventListener('DOMContentLoaded', () => {
      const nav = document.getElementById('nav-links');
      document.querySelectorAll('.card[id]').forEach(el => {
        const title = el.querySelector('.card-title, h2, summary');
        if (!title) return;
        const a = document.createElement('a');
        a.href = '#' + el.id;
        a.textContent = title.textContent.replace(/[▲▼]/g,'').trim();
        nav.appendChild(a);
      });
    });
    // Table sorting
    document.addEventListener('click', e => {
      const th = e.target.closest('th[data-sort]');
      if (!th) return;
      const table = th.closest('table');
      const col   = Array.from(th.parentElement.children).indexOf(th);
      const asc   = th.classList.toggle('sort-asc');
      th.classList.toggle('sort-desc', !asc);
      th.parentElement.querySelectorAll('th').forEach(t => {
        if (t !== th) t.classList.remove('sort-asc','sort-desc');
      });
      const tbody = table.querySelector('tbody');
      Array.from(tbody.querySelectorAll('tr'))
        .sort((a, b) => {
          const av = a.cells[col]?.dataset.val ?? a.cells[col]?.textContent ?? '';
          const bv = b.cells[col]?.dataset.val ?? b.cells[col]?.textContent ?? '';
          const an = parseFloat(av), bn = parseFloat(bv);
          if (!isNaN(an) && !isNaN(bn)) return asc ? an-bn : bn-an;
          return asc ? av.localeCompare(bv) : bv.localeCompare(av);
        })
        .forEach(r => tbody.appendChild(r));
    });
    """

    # ---- Build HTML sections ----

    def _card(title, body, anchor="", border_color=None, open_by_default=True):
        border_style = f"border-left:4px solid {border_color};" if border_color else ""
        anchor_attr  = f' id="{anchor}"' if anchor else ""
        open_attr    = " open" if open_by_default else ""
        return (f'<details class="card" style="{border_style}"{anchor_attr}{open_attr}>'
                f'<summary style="display:flex;justify-content:space-between;align-items:center;cursor:pointer">'
                f'<span class="card-title">{title}</span>'
                f'<span class="toggle-icon" style="font-size:10px;color:var(--subtle)"></span>'
                f'</summary>'
                f'<div class="card-body" style="margin-top:14px">{body}</div>'
                f'</details>')

    # Executive summary
    def _exec_summary():
        top_actions = actions[:3]
        action_items = ""
        pc = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
        for a in top_actions:
            c = pc.get(a["priority"], "#94a3b8")
            action_items += (f'<li style="margin-bottom:6px">'
                             f'<span style="background:{c};color:#fff;padding:1px 7px;border-radius:8px;font-size:10px;margin-right:6px">{a["priority"]}</span>'
                             f'<strong>{_h(a["action"])}</strong>'
                             + (f'<br><span style="font-size:11px;color:var(--muted);margin-left:52px">{_h(a["detail"])}</span>' if a.get("detail") else "")
                             + '</li>')
        trend_bits = []
        if growing:
            trend_bits.append(f'<span style="font-weight:700;color:#ef4444">▲ {len(growing)} growing</span>')
        if anomalies:
            trend_bits.append(f'<span style="font-weight:700;color:#f97316">{len(anomalies)} anomalies</span>')
        if saved_mts:
            trend_bits.append(f'<span style="font-weight:700;color:#22c55e">~${saved_cost:,.0f}/mo saved</span>')
        trend_html = " &nbsp;·&nbsp; ".join(trend_bits) if trend_bits else ""
        limit_html = (f'<span style="font-size:12px;color:var(--muted)">{pct_used}% of org MTS limit</span>'
                      if pct_used is not None else "")
        return f"""
  <div class="card" style="border-left:6px solid {grade_color};background:linear-gradient(135deg,var(--hover) 0%,var(--surface) 100%);margin-bottom:16px;color:var(--text)">
    <div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap">
      <div style="text-align:center;min-width:80px">
        <div style="font-size:56px;font-weight:900;line-height:1;color:{grade_color}">{grade}</div>
        <div style="font-size:12px;color:var(--muted);margin-top:2px">Governance Score</div>
        <div style="font-size:22px;font-weight:700;color:{grade_color}">{health_score}/100</div>
      </div>
      <div style="flex:1;min-width:200px;color:var(--text)">
        <div style="font-size:13px;color:var(--muted);margin-bottom:6px">
          <strong style="color:#ef4444">{len(critical)}</strong> Critical &nbsp;·&nbsp;
          <strong style="color:#f97316">{len(high)}</strong> High &nbsp;·&nbsp;
          <strong style="color:#eab308">{len(medium)}</strong> Medium &nbsp;·&nbsp;
          <strong>{total_mts:,}</strong> total MTS &nbsp;·&nbsp;
          <strong>~${total_cost:,.2f}/mo</strong>
        </div>
        <div style="margin-bottom:10px">{trend_html} {limit_html}</div>
        {"<ul style='margin:0;padding-left:0;list-style:none;color:var(--text)'>" + action_items + "</ul>" if action_items else ""}
      </div>
    </div>
  </div>"""

    # Recommended actions card
    def _actions_card():
        if not actions:
            return ""
        pc = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
        rows = ""
        for a in actions:
            c = pc.get(a["priority"], "#94a3b8")
            rows += (f'<tr>'
                     f'<td style="text-align:center"><span style="background:{c};color:#fff;padding:2px 8px;border-radius:9px;font-size:11px">{_h(a["priority"])}</span></td>'
                     f'<td style="font-size:12px;color:var(--muted)">{_h(a["category"])}</td>'
                     f'<td style="font-size:13px;font-weight:600">{_h(a["action"])}</td>'
                     f'<td style="font-size:11px;color:var(--muted)">{_h(a.get("detail",""))}</td>'
                     f'</tr>')
        body = f'<table><thead><tr><th style="text-align:center">Priority</th><th>Category</th><th>Action</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>'
        return _card("Recommended Actions", body, anchor="sec-actions",
                     border_color="#ef4444" if any(a["priority"]=="critical" for a in actions) else "#f97316")

    # Stat grid
    def _stat_grid():
        crit_c  = "#ef4444" if critical else "#94a3b8"
        high_c  = "#f97316" if high     else "#94a3b8"
        med_c   = "#eab308" if medium   else "#94a3b8"
        html  = '<div class="stat-grid">'
        html += f'<div class="stat"><div class="val" style="color:{crit_c}">{len(critical)}</div><div class="lbl">Critical</div></div>'
        html += f'<div class="stat"><div class="val" style="color:{high_c}">{len(high)}</div><div class="lbl">High</div></div>'
        html += f'<div class="stat"><div class="val" style="color:{med_c}">{len(medium)}</div><div class="lbl">Medium</div></div>'
        html += f'<div class="stat"><div class="val">{total_mts:,}</div><div class="lbl">Total MTS</div></div>'
        html += f'<div class="stat"><div class="val">~${total_cost:,.0f}</div><div class="lbl">Est. $/mo</div></div>'
        if saved_mts:
            html += f'<div class="stat"><div class="val" style="color:#22c55e">~${saved_cost:,.0f}</div><div class="lbl">Saved $/mo</div></div>'
        if pct_used is not None:
            pc_c = "#ef4444" if pct_used > 80 else "#f97316" if pct_used > 60 else "#22c55e"
            html += f'<div class="stat"><div class="val" style="color:{pc_c}">{pct_used}%</div><div class="lbl">Org Limit Used</div></div>'
        html += f'<div class="stat"><div class="val">{len(growing)}</div><div class="lbl">Growing</div></div>'
        html += f'<div class="stat"><div class="val">{len(anomalies)}</div><div class="lbl">Anomalies</div></div>'
        html += '</div>'
        # alert banners
        if growing:
            names = ", ".join(f"<code>{_h(f['metric'])}</code>" for f in growing[:3])
            html += f'<div style="background:#ef444422;border:1px solid #ef444466;border-radius:8px;padding:10px 14px;margin-top:12px;font-size:12px;color:var(--text)">📈 <strong>{len(growing)} metric(s) growing &gt;20%</strong> since last scan: {names}{"..." if len(growing)>3 else ""}</div>'
        if new_metrics:
            html += f'<div style="background:#3b82f622;border:1px solid #3b82f666;border-radius:8px;padding:10px 14px;margin-top:8px;font-size:12px;color:var(--text)">🆕 <strong>{len(new_metrics)} new metric(s)</strong> appeared since last scan</div>'
        if saved_mts:
            html += f'<div style="background:#22c55e22;border:1px solid #22c55e66;border-radius:8px;padding:10px 14px;margin-top:8px;font-size:12px;color:var(--text)">✅ <strong>Cumulative savings:</strong> {saved_mts:,} MTS / ~${saved_cost:,.2f}/mo across {len(all_resolved)} resolved metric(s)</div>'
        return html

    def _pills(values, color):
        """Render a list of values as small coloured pills."""
        if not values:
            return '<span style="color:var(--subtle);font-size:11px">—</span>'
        return "".join(
            f'<span style="display:inline-block;background:{color}22;border:1px solid {color}55;'
            f'border-radius:5px;padding:1px 7px;margin:1px 2px;font-size:11px;color:{color};white-space:nowrap">'
            f'{_h(v)}</span>'
            for v in values
        )

    # Top offenders table
    def offenders_table(rows, limit=None):
        h = '<button class="btn-expand-cols" onclick="toggleExtraCols(this,\'offenders-tbl\')">Show more columns ▼</button>'
        h += '<div style="overflow-x:auto"><table id="offenders-tbl"><thead><tr>'
        h += '<th data-sort>Rank</th><th data-sort>Metric</th><th data-sort>MTS</th>'
        h += '<th data-sort>Est. Cost/Mo</th><th data-sort>Severity</th>'
        h += '<th data-sort>Trend</th><th data-sort>Source</th>'
        h += '<th data-sort>Worst Dimension</th>'
        h += '<th>Services</th>'
        h += '<th class="col-extra">Environments</th><th class="col-extra">Cluster / NS</th>'
        h += '</tr></thead><tbody>'
        for i, f in enumerate(rows[:limit] if limit else rows, 1):
            worst       = f["worst_dim"] or "—"
            worst_count = f["worst_dim_info"]["unique_values"] if f["worst_dim_info"] else 0
            cost        = f["mts_count"] * MTS_COST_PER_MONTH
            attr        = f.get("attribution", {})
            services    = attr.get("services", f["attributed_to"])
            envs        = attr.get("environments", [])
            clusters    = attr.get("clusters", [])
            namespaces  = attr.get("namespaces", [])
            clus_ns     = clusters + [f"ns:{n}" for n in namespaces]
            anomaly_tag = (f' <span style="background:#ef4444;color:#fff;border-radius:4px;'
                           f'padding:1px 5px;font-size:10px;font-weight:700">'
                           f'{f["baseline_ratio"]}x</span>'
                           if f.get("anomaly") else "")
            detail_link = f' <a href="#detail-{i}" style="font-size:10px;color:#3b82f6;text-decoration:none" title="Go to detailed finding">↗</a>'
            h += '<tr>'
            h += f'<td data-val="{i}">{i}</td>'
            h += f'<td><span class="metric-name">{_h(f["metric"])}</span>{anomaly_tag}{detail_link}</td>'
            h += f'<td data-val="{f["mts_count"]}">{f["mts_count"]:,}</td>'
            h += f'<td data-val="{cost}">~${cost:,.2f}</td>'
            h += f'<td>{_sev_badge(f["severity"])}</td>'
            h += f'<td>{_trend_badge(f.get("trend",""), f.get("growth_pct"))}</td>'
            h += f'<td style="font-size:11px;color:var(--muted)">{_h(f["instr_source"])}</td>'
            h += f'<td><span class="dim-name">{_h(worst)}</span> <span style="color:var(--muted);font-size:11px">({worst_count:,})</span></td>'
            h += f'<td>{_pills(services[:3], "#3b82f6")}</td>'
            h += f'<td class="col-extra">{_pills(envs[:3], "#22c55e")}</td>'
            h += f'<td class="col-extra">{_pills(clus_ns[:3], "#8b5cf6")}</td>'
            h += '</tr>'
        h += '</tbody></table></div>'
        return h

    # Build per-service environment + cluster index for scorecard
    service_envs     = defaultdict(set)
    service_clusters = defaultdict(set)
    for f in findings:
        attr = f.get("attribution", {})
        for svc in attr.get("services", f["attributed_to"]):
            for e in attr.get("environments", []):
                service_envs[svc].add(e)
            for c in attr.get("clusters", []):
                service_clusters[svc].add(c)
            for n in attr.get("namespaces", []):
                service_clusters[svc].add(f"ns:{n}")

    def scorecard_table():
        h = '<table><thead><tr><th data-sort>Rank</th><th data-sort>Service</th>'
        h += '<th data-sort>Total MTS</th><th data-sort>Est. Cost/Mo</th>'
        h += '<th data-sort>Metrics</th><th data-sort>% of Total</th>'
        h += '<th>Environments</th><th>Cluster / NS</th></tr></thead><tbody>'
        for rank, (svc, svc_total) in enumerate(sorted(service_mts.items(), key=lambda x: -x[1]), 1):
            pct       = round(svc_total / total_mts * 100, 1) if total_mts else 0
            cost      = svc_total * MTS_COST_PER_MONTH
            n_metrics = len(service_metrics[svc])
            bar       = f'<div style="height:6px;background:#3b82f6;width:{min(pct*2,100)}%;border-radius:3px;margin-top:4px"></div>'
            envs      = sorted(service_envs.get(svc, []))
            clus_ns   = sorted(service_clusters.get(svc, []))
            h += f'<tr><td data-val="{rank}">{rank}</td><td><code style="font-size:12px">{_h(svc)}</code></td>'
            h += f'<td data-val="{svc_total}">{svc_total:,}</td>'
            h += f'<td data-val="{cost}">~${cost:,.2f}</td>'
            h += f'<td>{n_metrics}</td>'
            h += f'<td data-val="{pct}">{pct}%{bar}</td>'
            h += f'<td>{_pills(envs[:4], "#22c55e")}</td>'
            h += f'<td>{_pills(clus_ns[:3], "#8b5cf6")}</td>'
            h += '</tr>'
        h += '</tbody></table>'
        return h

    # Resolved findings table
    def resolved_table():
        if not all_resolved:
            return '<p style="color:var(--muted)">No resolved findings yet.</p>'
        current_map = {f["metric"]: f["mts_count"] for f in findings}
        max_saved   = max((r[1] - current_map.get(r[0], r[3]) for r in all_resolved), default=1)
        h = '<table><thead><tr><th>Metric</th><th data-sort>Peak MTS</th>'
        h += '<th data-sort>Current MTS</th><th data-sort>MTS Saved</th>'
        h += '<th>Savings Bar</th>'
        h += '<th data-sort>Cost Saved/Mo</th><th data-sort>Reduction</th>'
        h += '<th>Resolved At</th><th>How</th></tr></thead><tbody>'
        for row in all_resolved:
            metric, peak_mts, peak_at, resolved_mts, resolved_at, reduction_pct, manual = row
            current    = current_map.get(metric, resolved_mts)
            mts_saved  = peak_mts - current
            cost_saved = mts_saved * MTS_COST_PER_MONTH
            how        = "manual" if manual else "auto"
            bar_pct    = min(100, round(mts_saved / max(1, max_saved) * 100))
            bar_html   = (f'<div style="display:flex;align-items:center;gap:6px">'
                          f'<div style="flex:1;height:8px;background:var(--border);border-radius:4px;min-width:80px">'
                          f'<div class="savings-bar" style="width:{bar_pct}%"></div></div>'
                          f'<span style="font-size:10px;color:var(--muted)">{bar_pct}%</span>'
                          f'</div>')
            h += f'<tr><td><span class="metric-name">{_h(metric)}</span></td>'
            h += f'<td data-val="{peak_mts}">{peak_mts:,}</td>'
            h += f'<td data-val="{current}">{current:,}</td>'
            h += f'<td data-val="{mts_saved}">{mts_saved:,}</td>'
            h += f'<td>{bar_html}</td>'
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

    def _group_box(title_html, group, dim, dim_info):
        """Render one duplicate-group box with cost, savings, fix YAML + Copy button."""
        import math as _m
        group_mts  = sum(f["mts_count"] for f in group)
        group_cost = group_mts * MTS_COST_PER_MONTH
        # Savings estimate: dropping worst_dim typically reduces MTS by 60-90%; use 70% as conservative estimate
        est_saved_mts  = int(group_mts * 0.70)
        est_saved_cost = est_saved_mts * MTS_COST_PER_MONTH
        fix  = generate_fix_yaml(dim, [f["metric"] for f in group], dim_info or {})
        filt = fix["filter_processor"]
        tran = fix["transform_processor"]
        filt_js = filt.replace("\\","\\\\").replace("`","\\`")
        tran_js = tran.replace("\\","\\\\").replace("`","\\`")
        h  = f'<div class="group-box">'
        h += f'<h4>{title_html}</h4>'
        h += (f'<p style="margin-bottom:8px">'
              f'<strong>{group_mts:,} combined MTS</strong> &middot; ~${group_cost:,.2f}/mo &middot; '
              f'{len(group)} metrics &middot; '
              f'<span style="color:#22c55e;font-weight:600">Est. savings if fixed: ~{est_saved_mts:,} MTS / ~${est_saved_cost:,.2f}/mo</span>'
              f' &middot; <em>one fix resolves all {len(group)}</em></p>')
        h += '<table><thead><tr><th>Metric</th><th data-sort>MTS</th><th>Cost/Mo</th><th>Severity</th></tr></thead><tbody>'
        for f in sorted(group, key=lambda x: -x["mts_count"]):
            fc = f["mts_count"] * MTS_COST_PER_MONTH
            h += f'<tr><td><span class="metric-name">{_h(f["metric"])}</span></td>'
            h += f'<td data-val="{f["mts_count"]}">{f["mts_count"]:,}</td>'
            h += f'<td data-val="{fc}">~${fc:,.2f}</td>'
            h += f'<td>{_sev_badge(f["severity"])}</td></tr>'
        h += '</tbody></table>'
        h += f'<details style="margin-top:10px"><summary style="cursor:pointer;font-size:12px;color:#3b82f6;font-weight:600">Fix: drop <code>{_h(dim)}</code> (OTel Collector YAML)</summary>'
        h += f'<div style="margin-top:6px"><button class="copy-yaml-btn" onclick="copyYaml(this,`{filt_js}`)">Copy</button>'
        h += f'<pre>{_h(filt)}</pre>'
        h += f'<details><summary style="cursor:pointer;font-size:11px;color:var(--muted)">Alternative: hash instead of drop</summary>'
        h += f'<button class="copy-yaml-btn" onclick="copyYaml(this,`{tran_js}`)">Copy</button>'
        h += f'<pre>{_h(tran)}</pre></details></div>'
        h += '</details></div>'
        return h

    def groups_html():
        h = ""
        if dim_multi:
            h += '<h3 style="margin-bottom:12px">Grouped by Shared Worst Dimension</h3>'
            for dim, group in sorted(dim_multi.items(), key=lambda x: -sum(f["mts_count"] for f in x[1])):
                dim_info  = group[0]["worst_dim_info"] or {}
                pat_badge = (f' <span class="badge" style="background:#d73a49">{_h(dim_info["pattern"])}</span>'
                             if dim_info.get("pattern") else "")
                uv = dim_info.get("unique_values", 0)
                title_html = f'<span class="dim-name">{_h(dim)}</span> &mdash; {uv:,} unique values{pat_badge}'
                h += _group_box(title_html, group, dim, dim_info)
        if prefix_multi:
            h += '<h3 style="margin-top:24px;margin-bottom:12px">Grouped by Metric Name Prefix (Histogram Family)</h3>'
            h += '<p style="font-size:12px;color:var(--muted);margin-bottom:14px">Metrics sharing the same base name (e.g. <code>http_request_duration_{bucket,count,sum}</code>) — fixing the worst dimension on any one resolves all siblings.</p>'
            for prefix, group in sorted(prefix_multi.items(), key=lambda x: -sum(f["mts_count"] for f in x[1])):
                # Use the worst dim from highest-MTS member
                anchor_f  = max(group, key=lambda x: x["mts_count"])
                worst_dim = anchor_f.get("worst_dim") or "unknown"
                dim_info  = anchor_f.get("worst_dim_info") or {}
                title_html = f'<code style="font-size:13px">{_h(prefix)}_*</code> &mdash; {len(group)} metric variants'
                h += _group_box(title_html, group, worst_dim, dim_info)
        return h

    # Detailed findings
    def detailed_html():
        h = ""
        for i, f in enumerate(findings, 1):
            attr      = f.get("attribution", {})
            sev       = f["severity"]
            cost      = f["mts_count"] * MTS_COST_PER_MONTH
            services  = attr.get("services",     f["attributed_to"])
            envs      = attr.get("environments", [])
            clusters  = attr.get("clusters",     [])
            namespaces= attr.get("namespaces",   [])
            pods      = attr.get("pods",         [])
            sdk       = attr.get("sdk",          "")

            # Trend string
            trend_str = f.get("trend", "")
            if f.get("prev_count") is not None and f.get("growth_pct") is not None:
                gpct = int(f["growth_pct"] * 100)
                trend_str += f" ({f['prev_count']:,} → {f['mts_count']:,}, {'+' if gpct >= 0 else ''}{gpct}%)"

            anomaly_html = ""
            if f.get("anomaly"):
                anomaly_html = (f'<span style="background:#ef4444;color:#fff;border-radius:5px;'
                                f'padding:2px 8px;font-size:11px;font-weight:700;margin-left:8px">'
                                f'ANOMALY {f["baseline_ratio"]}x baseline ({f["baseline_samples"]} samples)</span>')

            h += (f'<details class="finding" id="detail-{i}">'
                  f'<summary>{i}. <span class="metric-name">{_h(f["metric"])}</span>'
                  f' &nbsp; {_sev_badge(sev)} &nbsp; {f["mts_count"]:,} MTS &nbsp; ~${cost:,.2f}/mo'
                  f'{anomaly_html}</summary>')
            h += '<div style="padding:14px 0 6px">'

            # ── Context block ──────────────────────────────────────────────
            h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px;margin-bottom:14px">'

            def _ctx_cell(label, content):
                return (f'<div style="background:var(--hover);border:1px solid var(--border);'
                        f'border-radius:8px;padding:10px 12px">'
                        f'<div style="font-size:10px;font-weight:700;text-transform:uppercase;'
                        f'letter-spacing:.05em;color:var(--subtle);margin-bottom:6px">{label}</div>'
                        f'{content}</div>')

            h += _ctx_cell("Services",     _pills(services,   "#3b82f6") if services  != ["unknown"] else '<span style="color:var(--subtle);font-size:11px">unknown</span>')
            h += _ctx_cell("Environments", _pills(envs,       "#22c55e") if envs       else '<span style="color:var(--subtle);font-size:11px">not detected</span>')
            h += _ctx_cell("Clusters",     _pills(clusters,   "#8b5cf6") if clusters   else '<span style="color:var(--subtle);font-size:11px">not detected</span>')
            if namespaces:
                h += _ctx_cell("Namespaces", _pills(namespaces, "#6366f1"))
            if pods:
                h += _ctx_cell(f"Sample Pods ({len(pods)})", _pills(pods, "#f97316"))

            # Instrumentation source cell
            h += _ctx_cell("Instrumentation",
                            f'<span style="font-size:12px;font-weight:600">{_h(f["instr_source"])}</span>'
                            + (f'<br><span style="font-size:11px;color:var(--muted)">{_h(f["instr_desc"])}</span>'
                               if f.get("instr_desc") else ""))

            # Metric metadata cell
            type_badge  = f'<span style="background:var(--hover);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-size:11px">{_h(f["type"])}</span>'
            custom_badge= (f' <span style="background:#f9731622;color:#f97316;border:1px solid #f9731644;border-radius:4px;padding:1px 6px;font-size:11px">custom</span>'
                           if f.get("custom") else
                           f' <span style="background:#22c55e22;color:#22c55e;border:1px solid #22c55e44;border-radius:4px;padding:1px 6px;font-size:11px">builtin</span>')
            limit_line  = (f'<br><span style="font-size:11px;color:var(--muted)">{f["limit_pct"]}% of org limit</span>'
                           if f.get("limit_pct") is not None else "")
            h += _ctx_cell("Metric Type", type_badge + custom_badge + limit_line)

            # Trend / history cell
            peak_line = ""
            if f.get("peak_mts") and f["peak_mts"] != f["mts_count"]:
                peak_line = (f'<br><span style="font-size:11px;color:var(--muted)">'
                             f'Peak: {f["peak_mts"]:,} MTS on {_h(str(f["peak_at"])[:10])}</span>')
            h += _ctx_cell("Trend",
                            _trend_badge(f.get("trend",""), f.get("growth_pct"))
                            + (f' <span style="font-size:11px;color:var(--muted)">{_h(trend_str)}</span>'
                               if trend_str else "")
                            + peak_line)

            if sdk:
                h += _ctx_cell("SDK", f'<span style="font-size:11px;font-family:monospace">{_h(sdk)}</span>')

            h += '</div>'  # end context grid

            # ── Dimension table ────────────────────────────────────────────
            if f["dimensions"]:
                worst_val = max((info["unique_values"] for info in f["dimensions"].values()), default=1)
                h += ('<table style="margin-bottom:10px"><thead><tr>'
                      '<th data-sort>Dimension</th>'
                      '<th data-sort>Unique Values</th>'
                      '<th>% of Worst</th>'
                      '<th>Anti-pattern</th>'
                      '<th>Sample Values</th>'
                      '</tr></thead><tbody>')
                for dim, info in list(f["dimensions"].items())[:10]:
                    pattern = info["pattern"] or "—"
                    samples = " &nbsp; ".join(f'<code style="font-size:11px">{_h(v)}</code>'
                                              for v in info["sample_values"][:4])
                    pat_color = "#ef4444" if info["pattern"] else "var(--muted)"
                    pct_worst = round(info["unique_values"] / max(1, worst_val) * 100)
                    bar_color = "#ef4444" if pct_worst >= 80 else "#f97316" if pct_worst >= 40 else "#3b82f6"
                    bar_html  = (f'<div style="display:flex;align-items:center;gap:6px">'
                                 f'<div style="flex:1;height:6px;background:var(--border);border-radius:3px;min-width:60px">'
                                 f'<div style="height:6px;background:{bar_color};width:{pct_worst}%;border-radius:3px"></div></div>'
                                 f'<span style="font-size:11px;color:var(--muted);min-width:30px">{pct_worst}%</span>'
                                 f'</div>')
                    h += (f'<tr>'
                          f'<td><span class="dim-name">{_h(dim)}</span></td>'
                          f'<td data-val="{info["unique_values"]}" style="font-weight:700">{info["unique_values"]:,}</td>'
                          f'<td data-val="{pct_worst}">{bar_html}</td>'
                          f'<td><span style="color:{pat_color};font-size:11px">{_h(pattern)}</span></td>'
                          f'<td style="font-size:11px">{samples}</td>'
                          f'</tr>')
                h += '</tbody></table>'

            # ── AI Remediation ─────────────────────────────────────────────
            # ── OTel Collector Fix YAML ────────────────────────────────────
            if f["worst_dim"]:
                dim_info = f.get("worst_dim_info") or {}
                fix = generate_fix_yaml(f["worst_dim"], [f["metric"]], dim_info)
                filter_yaml    = fix["filter_processor"]
                transform_yaml = fix["transform_processor"]
                filter_js    = filter_yaml.replace("\\","\\\\").replace("`","\\`")
                transform_js = transform_yaml.replace("\\","\\\\").replace("`","\\`")
                h += (f'<details style="margin-top:8px">'
                      f'<summary style="cursor:pointer;font-size:12px;color:#3b82f6;font-weight:600">'
                      f'OTel Collector Fix (YAML)</summary>'
                      f'<div style="margin-top:8px">'
                      f'<button class="copy-yaml-btn" onclick="copyYaml(this, `{filter_js}`)">Copy</button>'
                      f'<pre>{_h(filter_yaml)}</pre>'
                      f'<details style="margin-top:4px"><summary style="cursor:pointer;font-size:11px;color:var(--muted)">Alternative: hash instead of drop</summary>'
                      f'<button class="copy-yaml-btn" onclick="copyYaml(this, `{transform_js}`)">Copy</button>'
                      f'<pre>{_h(transform_yaml)}</pre></details>'
                      f'</div></details>')

            if use_claude and sev in ("CRITICAL", "HIGH"):
                print(f"  Generating AI remediation for {f['metric']}...")
                remediation = generate_remediation(f)
                h += (f'<details style="margin-top:6px">'
                      f'<summary style="cursor:pointer;font-size:12px;color:#3b82f6;font-weight:600">'
                      f'AI Remediation</summary>'
                      f'<pre style="margin-top:8px">{_h(remediation)}</pre></details>')

            h += '</div></details>'
        return h

    # Source breakdown
    def _source_breakdown_html():
        source_mts     = defaultdict(int)
        source_metrics = defaultdict(set)
        source_cost    = defaultdict(float)
        for f in findings:
            src = f["instr_source"]
            source_mts[src]     += f["mts_count"]
            source_metrics[src].add(f["metric"])
            source_cost[src]    += f["mts_count"] * MTS_COST_PER_MONTH
        if not source_mts:
            return '<p style="color:var(--muted)">No findings to break down.</p>'
        max_src_mts = max(source_mts.values(), default=1)
        h  = '<table><thead><tr>'
        h += '<th data-sort>Source</th><th data-sort>Metrics</th>'
        h += '<th data-sort>Total MTS</th><th>MTS Share</th>'
        h += '<th data-sort>Est. Cost/Mo</th></tr></thead><tbody>'
        for src, smts in sorted(source_mts.items(), key=lambda x: -x[1]):
            pct   = round(smts / max(1, total_mts) * 100, 1)
            bar_w = round(smts / max_src_mts * 100)
            bar_c = "#3b82f6" if "otel" in src.lower() else "#8b5cf6" if "splunk" in src.lower() else "#f97316"
            bar_html = (f'<div style="display:flex;align-items:center;gap:6px">'
                        f'<div style="flex:1;height:8px;background:var(--border);border-radius:4px;min-width:80px">'
                        f'<div style="height:8px;background:{bar_c};width:{bar_w}%;border-radius:4px"></div></div>'
                        f'<span style="font-size:11px;color:var(--muted)">{pct}%</span></div>')
            h += (f'<tr><td style="font-weight:600">{_h(src)}</td>'
                  f'<td data-val="{len(source_metrics[src])}">{len(source_metrics[src])}</td>'
                  f'<td data-val="{smts}">{smts:,}</td>'
                  f'<td>{bar_html}</td>'
                  f'<td data-val="{source_cost[src]}">~${source_cost[src]:,.2f}</td></tr>')
        h += '</tbody></table>'
        return h

    # Ignored patterns
    def ignored_html():
        if not ignored_patterns:
            return '<p style="color:var(--muted)">No patterns in ignore list.</p>'
        h = '<table><thead><tr><th>Pattern</th><th>Reason</th><th>Since</th></tr></thead><tbody>'
        for pattern, reason, ignored_at in ignored_patterns:
            h += f'<tr><td><code>{_h(pattern)}</code></td><td>{_h(reason or "—")}</td><td>{_h(ignored_at[:10])}</td></tr>'
        h += '</tbody></table>'
        return h

    # Scan history card
    def _history_card():
        if not scan_history:
            return ""
        import math as _m

        # scan_history is newest-first; reverse for chronological order in sparkline
        chrono = list(reversed(scan_history))
        mts_vals = [row[2] for row in chrono]

        # Build inline SVG sparkline (80×24 px)
        def _sparkline(vals):
            if len(vals) < 2:
                return ""
            mn, mx = min(vals), max(vals)
            rng = mx - mn or 1
            W, H = 80, 24
            pts = []
            for idx, v in enumerate(vals):
                x = round(idx / (len(vals) - 1) * W, 1)
                y = round(H - (v - mn) / rng * (H - 4) - 2, 1)
                pts.append(f"{x},{y}")
            path = " ".join(pts)
            last_color = "#ef4444" if vals[-1] > vals[0] else "#22c55e"
            return (f'<svg width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
                    f'style="display:inline-block;vertical-align:middle" xmlns="http://www.w3.org/2000/svg">'
                    f'<polyline points="{path}" fill="none" stroke="{last_color}" stroke-width="1.5" stroke-linejoin="round"/>'
                    f'</svg>')

        sparkline_svg = _sparkline(mts_vals)

        # Build rows chronologically so deltas are vs previous scan, then reverse for newest-first display
        row_htmls = []
        prev_mts = None
        for row in chrono:
            scanned_at, total_metrics, t_mts, crit, hi, med, ign = row
            cost   = t_mts * MTS_COST_PER_MONTH
            crit_c = "#ef4444" if crit else "var(--muted)"
            if prev_mts is not None:
                delta     = t_mts - prev_mts
                delta_pct = round(delta / max(1, prev_mts) * 100, 1)
                sign      = "+" if delta >= 0 else ""
                dc        = "#ef4444" if delta > 0 else "#22c55e" if delta < 0 else "var(--muted)"
                delta_html = f'<span style="color:{dc};font-size:11px;font-weight:600">{sign}{delta:,} ({sign}{delta_pct}%)</span>'
            else:
                delta_html = '<span style="color:var(--muted);font-size:11px">—</span>'
            row_htmls.append(
                f'<tr>'
                f'<td style="font-size:12px">{_h(scanned_at[:16].replace("T"," "))}</td>'
                f'<td style="text-align:center">{total_metrics:,}</td>'
                f'<td style="text-align:center;font-weight:700">{t_mts:,}</td>'
                f'<td style="text-align:center">{delta_html}</td>'
                f'<td style="text-align:center">~${cost:,.2f}</td>'
                f'<td style="text-align:center;color:{crit_c};font-weight:700">{crit}</td>'
                f'<td style="text-align:center">{hi}</td>'
                f'<td style="text-align:center">{med}</td>'
                f'<td style="text-align:center;color:var(--muted)">{ign}</td>'
                f'</tr>'
            )
            prev_mts = t_mts
        rows = "".join(reversed(row_htmls))

        sparkline_header = (f' &nbsp; {sparkline_svg}' if sparkline_svg else "")
        body = (f'<div style="margin-bottom:12px;font-size:12px;color:var(--muted)">'
                f'MTS trend across scans:{sparkline_header}</div>'
                f'<table><thead><tr>'
                f'<th data-sort>Date</th><th data-sort style="text-align:center">Metrics</th>'
                f'<th data-sort style="text-align:center">Total MTS</th>'
                f'<th data-sort style="text-align:center">Δ MTS</th>'
                f'<th data-sort style="text-align:center">Est. Cost/Mo</th>'
                f'<th data-sort style="text-align:center">Critical</th><th data-sort style="text-align:center">High</th>'
                f'<th data-sort style="text-align:center">Medium</th><th data-sort style="text-align:center">Ignored</th>'
                f'</tr></thead><tbody>{rows}</tbody></table>')
        return _card(f"Scan History ({len(scan_history)} scans)", body, anchor="sec-history", open_by_default=True)

    gen_time   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    limit_line = f" &middot; Org limit: {mts_limit:,} ({pct_used}% used)" if mts_limit else ""

    # Build section cards
    overview_body       = _stat_grid()
    offenders_body      = offenders_table(findings, limit=50)
    scorecard_body      = scorecard_table()
    _groups_result      = groups_html()
    groups_body         = _groups_result or '<p style="color:var(--muted)">No duplicate groups found.</p>'
    source_body         = _source_breakdown_html()
    resolved_body       = resolved_table()
    detailed_body       = (f'<p style="margin-bottom:12px;color:var(--muted);font-size:12px">Click a metric to expand dimension analysis and AI remediation.</p>'
                           + detailed_html())
    ignored_body        = ignored_html()

    sticky_risk = ""
    if critical:
        sticky_risk += f'<span class="sb-risk">{len(critical)} CRITICAL</span>'
    if growing:
        sticky_risk += f' <span class="sb-warn">{len(growing)} GROWING</span>'

    html = f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Cardinality Governance — {_h(REALM)}</title>
  <style>{css}</style>
</head>
<body>

  <div id="sticky-bar">
    <span class="sb-grade" style="color:{grade_color}">{grade}</span>
    <span style="color:#94a3b8">{health_score}/100</span>
    <span class="sb-sep">|</span>
    <span>{len(critical)} critical &nbsp; {len(high)} high &nbsp; {len(medium)} medium</span>
    <span class="sb-sep">|</span>
    <span>{total_mts:,} MTS &nbsp; ~${total_cost:,.2f}/mo</span>
    {f'<span class="sb-sep">|</span> {sticky_risk}' if sticky_risk else ""}
    <span class="sb-close" onclick="document.getElementById('sticky-bar').classList.add('hidden')" title="Dismiss">&#x2715;</span>
  </div>

  <div class="layout">

    <nav class="sidebar" id="sidebar">
      <div style="font-size:13px;font-weight:700;color:var(--text);margin-bottom:12px">Sections</div>
      <input id="search-box" type="text" placeholder="Search report..." oninput="filterReport(this.value)">
      <div id="nav-links"></div>
    </nav>

    <div class="page">
      <header>
        <div>
          <h1>Splunk Observability — Cardinality Governance</h1>
          <p>realm={_h(REALM)} &nbsp;|&nbsp; generated {_h(gen_time)} &nbsp;|&nbsp; {len(findings)} metrics analyzed{limit_line}</p>
        </div>
        <div class="header-controls">
          <button class="btn-toggle" onclick="toggleDark()">&#x1F319; Dark mode</button>
          <button class="btn-toggle" onclick="window.print()">&#x1F5A8; Print</button>
        </div>
      </header>

      {_exec_summary()}

      {_actions_card()}

      {_card("Overview", overview_body, anchor="sec-overview")}

      {_card("Top Offenders", offenders_body, anchor="sec-offenders",
             border_color="#ef4444" if critical else "#f97316")}

      {_card("Per-Service Scorecard", scorecard_body, anchor="sec-scorecard")}

      {_card("Instrumentation Source Breakdown", source_body, anchor="sec-sources", open_by_default=True)}

      {_card("Duplicate / Similar Groups",
             '<p style="font-size:12px;color:var(--muted);margin-bottom:14px">Metrics sharing the same high-cardinality dimension or name prefix — one OTel Collector fix resolves the whole group.</p>' + groups_body,
             anchor="sec-groups", open_by_default=bool(dim_multi or prefix_multi))}

      {_card(f"Resolved Findings ({len(all_resolved)})", resolved_body, anchor="sec-resolved",
             border_color="#22c55e" if all_resolved else None, open_by_default=bool(all_resolved))}

      {_card("Detailed Findings", detailed_body, anchor="sec-details", open_by_default=True)}

      {_history_card()}

      {_card(f"Ignored Patterns ({len(ignored_patterns)})", ignored_body, anchor="sec-ignored",
             open_by_default=True)}

      <p style="margin-top:32px;color:var(--subtle);font-size:11px">
        Generated by Metric Cardinality Governance &mdash; Splunk Observability Cloud
      </p>
    </div>
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
# MTS spike comparison
# ---------------------------------------------------------------------------

def db_get_snapshot_near_date(target_date_str):
    """
    Return a dict {metric: mts_count} from the scan run closest to target_date_str.
    target_date_str: 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM'
    Returns (snapshot_dict, actual_scanned_at) or ({}, None) if no data.
    """
    if not STATE_DB.exists():
        return {}, None
    conn = db_connect()
    row = conn.execute(
        """SELECT scanned_at FROM scans
           WHERE realm=?
           ORDER BY ABS(JULIANDAY(scanned_at) - JULIANDAY(?)) ASC
           LIMIT 1""",
        (REALM, target_date_str)
    ).fetchone()
    if not row:
        conn.close()
        return {}, None
    nearest_ts = row[0]
    rows = conn.execute(
        """SELECT metric, mts_count FROM scans
           WHERE realm=? AND ABS(JULIANDAY(scanned_at) - JULIANDAY(?)) < 0.001
           ORDER BY mts_count DESC""",
        (REALM, nearest_ts)
    ).fetchall()
    conn.close()
    snapshot = {r[0]: r[1] for r in rows}
    return snapshot, nearest_ts


def fetch_live_snapshot(verbose=False):
    """
    Lightweight live snapshot: fetch all metrics + MTS counts without full analysis.
    Returns dict {metric_name: {"mts_count": N, "source": str, "services": [str], "token": str}}
    """
    tokens = fetch_tokens()
    token_map = {t.get("id", ""): t.get("name", "") for t in tokens}

    metrics = fetch_metrics()
    if not metrics:
        return {}

    snapshot = {}
    total = len(metrics)
    for i, metric in enumerate(metrics):
        name = metric.get("name", "")
        if verbose:
            print(f"  [{i+1}/{total}] {name}", end="\r", flush=True)
        mts_list  = fetch_mts_for_metric(name, limit=10000)
        mts_count = len(mts_list)
        if mts_count == 0:
            continue
        source, _ = infer_instrumentation_source(name, mts_list)
        services  = attribute_to_team(mts_list, tokens)
        token_name = ""
        for mts in mts_list[:20]:
            tid = mts.get("dimensions", {}).get("tokenId", "")
            if tid and tid in token_map:
                token_name = token_map[tid]
                break
        snapshot[name] = {
            "mts_count": mts_count,
            "source":    source,
            "services":  services,
            "token":     token_name,
        }
    if verbose:
        print()
    return snapshot


def compare_snapshots(snap1, snap2):
    """
    Join two snapshots and return list of deltas, sorted by MTS increase desc.
    snap1/snap2: dict {metric: {"mts_count": N, ...}} or {metric: N} (from DB)
    Returns list of dicts with delta info.
    """
    def count(snap, key):
        v = snap.get(key, 0)
        return v if isinstance(v, int) else v.get("mts_count", 0)

    def meta(snap, key):
        v = snap.get(key, {})
        if isinstance(v, int):
            return {"source": "unknown", "services": [], "token": ""}
        return v

    all_keys = set(snap1) | set(snap2)
    deltas = []
    for metric in all_keys:
        mts1  = count(snap1, metric)
        mts2  = count(snap2, metric)
        delta = mts2 - mts1
        pct   = round((delta / mts1 * 100), 1) if mts1 > 0 else (100.0 if mts2 > 0 else 0.0)
        info  = meta(snap2, metric) if metric in snap2 else meta(snap1, metric)
        deltas.append({
            "metric":     metric,
            "mts1":       mts1,
            "mts2":       mts2,
            "delta":      delta,
            "pct_change": pct,
            "source":     info.get("source", "unknown"),
            "services":   info.get("services", []),
            "token":      info.get("token", ""),
        })
    return deltas


def cmd_compare(date1, date2, top_n=20, min_delta=100, show_new=True, show_dropped=False):
    """
    Compare MTS counts between two dates and show what drove spikes.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"\nMTS Spike Comparison  (realm={REALM})  generated {now_str}\n")

    LIVE_SENTINEL = "now"

    def load_snapshot(date_str, label):
        if date_str.lower() == LIVE_SENTINEL:
            print(f"  Fetching live snapshot for {label}...")
            snap = fetch_live_snapshot(verbose=True)
            ts   = datetime.now(timezone.utc).isoformat()
            print(f"  Live snapshot: {len(snap):,} metrics")
            return snap, ts
        else:
            snap, ts = db_get_snapshot_near_date(date_str)
            if snap:
                print(f"  Loaded stored snapshot for {label}: {len(snap):,} metrics from {ts[:16]}")
            else:
                print(f"  No stored snapshot near '{date_str}' — fetching live instead...")
                snap = fetch_live_snapshot(verbose=True)
                ts   = datetime.now(timezone.utc).isoformat()
                print(f"  Live snapshot: {len(snap):,} metrics")
            return snap, ts

    snap1, ts1 = load_snapshot(date1, "baseline")
    snap2, ts2 = load_snapshot(date2, "compared")

    if not snap1 and not snap2:
        print("\nNo data available for either date. Run 'scan' first to build history.")
        return

    print()
    deltas = compare_snapshots(snap1, snap2)

    increased    = sorted([d for d in deltas if d["delta"] >= min_delta], key=lambda x: -x["delta"])
    new_metrics  = [d for d in deltas if d["mts1"] == 0 and d["mts2"] > 0]
    dropped      = sorted([d for d in deltas if d["delta"] <= -min_delta], key=lambda x: x["delta"])

    total_mts1  = sum(d["mts1"] for d in deltas)
    total_mts2  = sum(d["mts2"] for d in deltas)
    total_delta = total_mts2 - total_mts1
    total_pct   = round(total_delta / total_mts1 * 100, 1) if total_mts1 > 0 else 0.0

    arrow = "+" if total_delta >= 0 else "-"
    cost1 = estimate_cost(total_mts1)
    cost2 = estimate_cost(total_mts2)
    print(f"  Baseline  ({ts1[:16]}):  {total_mts1:>10,} MTS   {cost1}")
    print(f"  Compared  ({ts2[:16]}):  {total_mts2:>10,} MTS   {cost2}")
    print(f"  Net change:               {arrow}{abs(total_delta):>9,} MTS  ({total_pct:+.1f}%)   "
          f"{estimate_cost(abs(total_delta))} {'added' if total_delta >= 0 else 'saved'}")
    print()

    if increased:
        print("=" * 120)
        print(f"  TOP MTS INCREASES  (>={min_delta:,} MTS delta)  --  {len(increased)} metric(s)")
        print("=" * 120)
        print(f"{'Rank':<5} {'Metric':<48} {'Baseline':>10} {'Current':>10} {'Delta':>10} {'Change':>8}  "
              f"{'Source':<25} {'Services / Token'}")
        print("-" * 145)
        for i, d in enumerate(increased[:top_n], 1):
            svc_str = ", ".join(d["services"][:3]) if d["services"] else "--"
            if d["token"]:
                svc_str += f" [{d['token']}]"
            pct_str  = f"+{d['pct_change']:.1f}%" if d["mts1"] > 0 else "NEW"
            base_str = f"{d['mts1']:,}" if d["mts1"] > 0 else "--"
            print(f"{i:<5} {d['metric']:<48} {base_str:>10} {d['mts2']:>10,} {d['delta']:>+10,} "
                  f"{pct_str:>8}  {d['source']:<25} {svc_str}")
        print()

        by_source = defaultdict(lambda: {"metrics": 0, "delta": 0})
        for d in increased:
            by_source[d["source"]]["metrics"] += 1
            by_source[d["source"]]["delta"]   += d["delta"]
        print(f"  Source breakdown for increased metrics:")
        print(f"  {'Source':<30} {'Metrics':>8} {'MTS Added':>12} {'Cost Added':>14}")
        print("  " + "-" * 68)
        for src, info in sorted(by_source.items(), key=lambda x: -x[1]["delta"]):
            print(f"  {src:<30} {info['metrics']:>8} {info['delta']:>12,} {estimate_cost(info['delta']):>14}/mo")
        print()

        by_token = defaultdict(lambda: {"metrics": 0, "delta": 0})
        for d in increased:
            tk = d["token"] or "(unknown token)"
            by_token[tk]["metrics"] += 1
            by_token[tk]["delta"]   += d["delta"]
        if not (len(by_token) == 1 and "(unknown token)" in by_token):
            print(f"  Token breakdown for increased metrics:")
            print(f"  {'Token':<35} {'Metrics':>8} {'MTS Added':>12}")
            print("  " + "-" * 58)
            for tk, info in sorted(by_token.items(), key=lambda x: -x[1]["delta"]):
                print(f"  {tk:<35} {info['metrics']:>8} {info['delta']:>12,}")
            print()

    if show_new and new_metrics:
        print("=" * 120)
        print(f"  NEW METRICS  (first seen in compared snapshot)  --  {len(new_metrics)} metric(s)")
        print("=" * 120)
        print(f"{'Rank':<5} {'Metric':<48} {'MTS':>10}  {'Source':<25} {'Services / Token'}")
        print("-" * 110)
        for i, d in enumerate(sorted(new_metrics, key=lambda x: -x["mts2"])[:top_n], 1):
            svc_str = ", ".join(d["services"][:3]) if d["services"] else "--"
            if d["token"]:
                svc_str += f" [{d['token']}]"
            print(f"{i:<5} {d['metric']:<48} {d['mts2']:>10,}  {d['source']:<25} {svc_str}")
        print()

    if show_dropped and dropped:
        print("=" * 120)
        print(f"  BIGGEST MTS DROPS  --  {len(dropped)} metric(s)")
        print("=" * 120)
        print(f"{'Rank':<5} {'Metric':<48} {'Baseline':>10} {'Current':>10} {'Delta':>10} {'Change':>8}  {'Source'}")
        print("-" * 120)
        for i, d in enumerate(dropped[:top_n], 1):
            print(f"{i:<5} {d['metric']:<48} {d['mts1']:>10,} {d['mts2']:>10,} {d['delta']:>+10,} "
                  f"{d['pct_change']:>7.1f}%  {d['source']}")
        print()

    if not increased and not new_metrics:
        print(f"  No metrics exceeded the minimum delta of {min_delta:,} MTS.")
        print(f"  Use --min-delta to lower the threshold.\n")


# ---------------------------------------------------------------------------
# Trace (APM) spike comparison
# ---------------------------------------------------------------------------

APM_URL = f"https://app.{REALM}.signalfx.com"
TOPO_URL = f"https://api.{REALM}.signalfx.com"

# Token for APM calls — same as metrics token
APM_HDR = {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}


def _apm_hdr():
    return {"X-SF-TOKEN": TOKEN, "Content-Type": "application/json"}


def fetch_services(environment=None, lookback_hours=2):
    """Return list of real (non-inferred) service names via topology API."""
    now   = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    start = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - lookback_hours * 3600))
    body  = {"timeRange": f"{start}/{now}"}
    if environment:
        body["tagFilters"] = [{"name": "sf_environment", "operator": "equals",
                               "value": environment, "scope": "global"}]
    try:
        resp = requests.post(f"{TOPO_URL}/v2/apm/topology", headers=_apm_hdr(), json=body, timeout=30)
        nodes = (resp.json().get("data") or {}).get("nodes", [])
        return [n["serviceName"] for n in nodes if not n.get("inferred")]
    except Exception:
        return []


def _start_analytics(parameters):
    body = {
        "operationName": "StartAnalyticsSearch",
        "variables": {"parameters": parameters},
        "query": "query StartAnalyticsSearch($parameters: JSON!) { startAnalyticsSearch(parameters: $parameters) }",
    }
    try:
        r = requests.post(f"{APM_URL}/v2/apm/graphql?op=StartAnalyticsSearch",
                          headers=_apm_hdr(), json=body, timeout=30)
        return ((r.json().get("data") or {}).get("startAnalyticsSearch") or {}).get("jobId")
    except Exception:
        return None


def _poll_analytics(job_id, max_polls=20):
    body = {
        "operationName": "GetAnalyticsSearch",
        "variables": {"jobId": job_id},
        "query": "query GetAnalyticsSearch($jobId: ID!) { getAnalyticsSearch(jobId: $jobId) }",
    }
    for _ in range(max_polls):
        time.sleep(2)
        try:
            r = requests.post(f"{APM_URL}/v2/apm/graphql?op=GetAnalyticsSearch",
                              headers=_apm_hdr(), json=body, timeout=30)
            d = ((r.json().get("data") or {}).get("getAnalyticsSearch") or {})
            sections = d.get("sections", [])
            if sections:
                return sections
        except Exception:
            pass
    return []


def fetch_trace_snapshot(start_ms, end_ms, environment=None, sample_limit=200):
    """
    Sample traces in [start_ms, end_ms] and return per-service aggregated metrics.
    Returns dict:
        {service_name: {
            "span_count": N,       # sampled spans (proportional to real volume)
            "trace_count": N,      # sampled traces (for this service as initiator)
            "error_count": N,      # spans with errors
            "error_rate": 0.0-1.0,
        }}
    Also returns metadata: {"sample_size": N, "time_range_ms": N}
    """
    trace_filters = []
    if environment:
        trace_filters.append({
            "traceFilter": {
                "tags": [{"tag": "sf_environment", "operation": "IN", "values": [environment]}]
            },
            "filterType": "traceFilter",
        })

    parameters = {
        "sharedParameters": {
            "timeRangeMillis": {"gte": start_ms, "lte": end_ms},
            "filters": trace_filters,
            "samplingFactor": 100,
        },
        "sectionsParameters": [
            {"sectionType": "traceExamples", "limit": sample_limit},
        ],
    }

    job_id = _start_analytics(parameters)
    if not job_id:
        return {}, {"sample_size": 0, "time_range_ms": end_ms - start_ms}

    sections = _poll_analytics(job_id)
    svc_spans  = defaultdict(int)
    svc_traces = defaultdict(int)
    svc_errors = defaultdict(int)
    sample_size = 0

    for section in sections:
        if section.get("sectionType") != "traceExamples":
            continue
        examples = section.get("legacyTraceExamples") or []
        sample_size = len(examples)
        for ex in examples:
            init_svc = ex.get("initiatingService", "unknown")
            svc_traces[init_svc] += 1
            for ssc in (ex.get("serviceSpanCounts") or []):
                svc  = ssc.get("service", "unknown")
                cnt  = ssc.get("spanCount", 0)
                errs = len(ssc.get("errors") or [])
                svc_spans[svc]  += cnt
                svc_errors[svc] += errs

    result = {}
    all_svcs = set(svc_spans) | set(svc_traces)
    for svc in all_svcs:
        spans  = svc_spans[svc]
        errors = svc_errors[svc]
        result[svc] = {
            "span_count":  spans,
            "trace_count": svc_traces[svc],
            "error_count": errors,
            "error_rate":  round(errors / spans, 4) if spans > 0 else 0.0,
        }

    meta = {"sample_size": sample_size, "time_range_ms": end_ms - start_ms}
    return result, meta


def db_save_trace_summary(scanned_at, environment, snapshot):
    """Persist a trace snapshot to SQLite for later comparison."""
    conn = db_connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trace_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at  TEXT NOT NULL,
            realm       TEXT NOT NULL,
            environment TEXT NOT NULL DEFAULT '',
            service     TEXT NOT NULL,
            span_count  INTEGER NOT NULL,
            trace_count INTEGER NOT NULL,
            error_count INTEGER NOT NULL,
            error_rate  REAL NOT NULL
        )
    """)
    conn.commit()
    rows = [
        (scanned_at, REALM, environment or "", svc,
         info["span_count"], info["trace_count"], info["error_count"], info["error_rate"])
        for svc, info in snapshot.items()
    ]
    conn.executemany(
        """INSERT INTO trace_snapshots
           (scanned_at, realm, environment, service, span_count, trace_count, error_count, error_rate)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        rows
    )
    conn.commit()
    conn.close()


def db_get_trace_snapshot_near_date(target_date_str, environment=None):
    """
    Load the stored trace snapshot closest to target_date_str.
    Returns (snapshot_dict, actual_ts) or ({}, None).
    """
    if not STATE_DB.exists():
        return {}, None
    conn = db_connect()
    # Ensure table exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trace_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT, realm TEXT, environment TEXT DEFAULT '',
            service TEXT, span_count INTEGER, trace_count INTEGER,
            error_count INTEGER, error_rate REAL
        )
    """)
    conn.commit()
    env_clause = "AND environment=?" if environment else ""
    env_args   = (environment,) if environment else ()

    row = conn.execute(
        f"""SELECT scanned_at FROM trace_snapshots
           WHERE realm=? {env_clause}
           ORDER BY ABS(JULIANDAY(scanned_at) - JULIANDAY(?)) ASC
           LIMIT 1""",
        (REALM,) + env_args + (target_date_str,)
    ).fetchone()
    if not row:
        conn.close()
        return {}, None

    nearest_ts = row[0]
    rows = conn.execute(
        f"""SELECT service, span_count, trace_count, error_count, error_rate
           FROM trace_snapshots
           WHERE realm=? {env_clause} AND ABS(JULIANDAY(scanned_at) - JULIANDAY(?)) < 0.001
           ORDER BY span_count DESC""",
        (REALM,) + env_args + (nearest_ts,)
    ).fetchall()
    conn.close()

    snapshot = {
        r[0]: {"span_count": r[1], "trace_count": r[2],
               "error_count": r[3], "error_rate": r[4]}
        for r in rows
    }
    return snapshot, nearest_ts


def cmd_scan_traces(environment=None, lookback_hours=1, save=True):
    """Quick trace scan: fetch snapshot and print per-service summary."""
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - int(lookback_hours * 3600 * 1000)
    ts       = datetime.now(timezone.utc).isoformat()

    env_label = environment or "(all environments)"
    print(f"\nTrace Scan  (realm={REALM})  env={env_label}  last {lookback_hours}h\n")

    snapshot, meta = fetch_trace_snapshot(start_ms, now_ms, environment=environment)
    if not snapshot:
        print("  No trace data found. Verify the environment name and that APM data is being ingested.")
        return

    print(f"  Sample: {meta['sample_size']} traces sampled over {lookback_hours}h\n")
    print(f"  {'Service':<40} {'Spans':>8} {'Traces':>8} {'Errors':>8} {'Err%':>7}")
    print("  " + "-" * 76)
    for svc, info in sorted(snapshot.items(), key=lambda x: -x[1]["span_count"]):
        err_pct = f"{info['error_rate']*100:.1f}%"
        print(f"  {svc:<40} {info['span_count']:>8,} {info['trace_count']:>8,} "
              f"{info['error_count']:>8,} {err_pct:>7}")

    if save:
        db_save_trace_summary(ts, environment or "", snapshot)
        print(f"\n  Snapshot saved to {STATE_DB} at {ts[:16]}")


def cmd_compare_traces(date1, date2, environment=None, top_n=20, min_delta=50,
                       show_new=True, show_dropped=False, lookback_hours=1):
    """
    Compare trace/span volumes between two dates, broken down by service.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    env_label = environment or "(all environments)"
    print(f"\nTrace Spike Comparison  (realm={REALM})  env={env_label}  generated {now_str}\n")

    now_ms = int(time.time() * 1000)
    window_ms = int(lookback_hours * 3600 * 1000)

    LIVE = "now"

    def load_snap(date_str, label):
        if date_str.lower() == LIVE:
            print(f"  Fetching live trace snapshot for {label} (last {lookback_hours}h)...")
            snap, meta = fetch_trace_snapshot(now_ms - window_ms, now_ms, environment=environment)
            ts = datetime.now(timezone.utc).isoformat()
            print(f"  Live: {meta['sample_size']} traces sampled, {len(snap)} services")
            if snap:
                db_save_trace_summary(ts, environment or "", snap)
            return snap, ts
        else:
            snap, ts = db_get_trace_snapshot_near_date(date_str, environment=environment)
            if snap:
                print(f"  Loaded stored trace snapshot for {label}: {len(snap)} services from {ts[:16]}")
            else:
                print(f"  No stored snapshot near \'{date_str}\' — fetching live instead...")
                snap, meta = fetch_trace_snapshot(now_ms - window_ms, now_ms, environment=environment)
                ts = datetime.now(timezone.utc).isoformat()
                print(f"  Live: {meta['sample_size']} traces sampled, {len(snap)} services")
                if snap:
                    db_save_trace_summary(ts, environment or "", snap)
            return snap, ts

    snap1, ts1 = load_snap(date1, "baseline")
    snap2, ts2 = load_snap(date2, "compared")

    if not snap1 and not snap2:
        print("\n  No data. Run \'trace-scan\' first to build history, or use \'now\' as a date.")
        return

    print()

    # Join snapshots
    all_svcs = set(snap1) | set(snap2)
    deltas = []
    for svc in all_svcs:
        s1 = snap1.get(svc, {"span_count": 0, "trace_count": 0, "error_count": 0, "error_rate": 0.0})
        s2 = snap2.get(svc, {"span_count": 0, "trace_count": 0, "error_count": 0, "error_rate": 0.0})
        span_delta  = s2["span_count"]  - s1["span_count"]
        trace_delta = s2["trace_count"] - s1["trace_count"]
        span_pct    = round(span_delta / s1["span_count"] * 100, 1) if s1["span_count"] > 0 else (100.0 if s2["span_count"] > 0 else 0.0)
        err1 = s1["error_rate"] * 100
        err2 = s2["error_rate"] * 100
        err_delta = round(err2 - err1, 2)
        deltas.append({
            "service":     svc,
            "spans1":      s1["span_count"],
            "spans2":      s2["span_count"],
            "span_delta":  span_delta,
            "span_pct":    span_pct,
            "traces1":     s1["trace_count"],
            "traces2":     s2["trace_count"],
            "err_rate1":   err1,
            "err_rate2":   err2,
            "err_delta":   err_delta,
        })

    total_spans1  = sum(d["spans1"]  for d in deltas)
    total_spans2  = sum(d["spans2"]  for d in deltas)
    total_delta   = total_spans2 - total_spans1
    total_pct     = round(total_delta / total_spans1 * 100, 1) if total_spans1 > 0 else 0.0

    arrow = "+" if total_delta >= 0 else "-"
    print(f"  Baseline  ({ts1[:16]}):  {total_spans1:>10,} spans sampled")
    print(f"  Compared  ({ts2[:16]}):  {total_spans2:>10,} spans sampled")
    print(f"  Net change:               {arrow}{abs(total_delta):>9,} spans  ({total_pct:+.1f}%)")
    print()
    print(f"  Note: span counts are from a {min(200, 200)}-trace sample per window.")
    print(f"  Use changes as relative indicators — larger absolute deltas = bigger real spike.")
    print()

    # Sections
    increased  = sorted([d for d in deltas if d["span_delta"] >= min_delta], key=lambda x: -x["span_delta"])
    new_svcs   = [d for d in deltas if d["spans1"] == 0 and d["spans2"] > 0]
    dropped    = sorted([d for d in deltas if d["span_delta"] <= -min_delta], key=lambda x: x["span_delta"])

    if increased:
        print("=" * 115)
        print(f"  TOP SPAN INCREASES  (>={min_delta} span delta)  --  {len(increased)} service(s)")
        print("=" * 115)
        print(f"  {'Service':<35} {'Baseline':>9} {'Current':>9} {'Delta':>9} {'Change':>8}  "
              f"{'ErrRate Baseline':>16} {'ErrRate Now':>12} {'Err Delta':>10}")
        print("  " + "-" * 113)
        for d in increased[:top_n]:
            pct_str  = f"+{d['span_pct']:.1f}%" if d["spans1"] > 0 else "NEW"
            base_str = f"{d['spans1']:,}" if d["spans1"] > 0 else "--"
            err_arrow = " (+" if d["err_delta"] > 0 else " (-" if d["err_delta"] < 0 else "  "
            err_str  = f"{err_arrow}{abs(d['err_delta']):.1f}pp)" if d["err_delta"] != 0 else ""
            print(f"  {d['service']:<35} {base_str:>9} {d['spans2']:>9,} {d['span_delta']:>+9,} "
                  f"{pct_str:>8}  {d['err_rate1']:>14.1f}%  {d['err_rate2']:>10.1f}%  "
                  f"{d['err_delta']:>+8.1f}pp{err_str}")
        print()

    if show_new and new_svcs:
        print("=" * 115)
        print(f"  NEW SERVICES  (first seen in compared snapshot)  --  {len(new_svcs)} service(s)")
        print("=" * 115)
        print(f"  {'Service':<35} {'Spans':>9}  {'Err%':>8}")
        print("  " + "-" * 56)
        for d in sorted(new_svcs, key=lambda x: -x["spans2"])[:top_n]:
            print(f"  {d['service']:<35} {d['spans2']:>9,}  {d['err_rate2']:>7.1f}%")
        print()

    if show_dropped and dropped:
        print("=" * 115)
        print(f"  BIGGEST SPAN DROPS  --  {len(dropped)} service(s)")
        print("=" * 115)
        print(f"  {'Service':<35} {'Baseline':>9} {'Current':>9} {'Delta':>9} {'Change':>8}")
        print("  " + "-" * 75)
        for d in dropped[:top_n]:
            print(f"  {d['service']:<35} {d['spans1']:>9,} {d['spans2']:>9,} "
                  f"{d['span_delta']:>+9,} {d['span_pct']:>+7.1f}%")
        print()

    if not increased and not new_svcs:
        print(f"  No services exceeded the minimum span delta of {min_delta}.")
        print(f"  Use --min-delta to lower the threshold or check the environment name.\n")


# ---------------------------------------------------------------------------
# Unified usage-compare (metrics + traces)
# ---------------------------------------------------------------------------

def cmd_usage_compare(date1, date2, environment=None, top_n=20,
                      metric_min_delta=100, trace_min_delta=10,
                      lookback_hours=1.0, show_dropped=False):
    """
    Unified post-incident comparison: runs metric MTS diff and trace span diff
    side-by-side, then prints a combined signal summary.
    """
    now_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    env_label = environment or "(all environments)"
    width     = 120

    print()
    print("=" * width)
    print(f"  USAGE COMPARE  |  realm={REALM}  |  env={env_label}  |  {now_str}")
    print(f"  Baseline: {date1}   vs   Compared: {date2}")
    print("=" * width)

    # ── Metrics section ───────────────────────────────────────────────────
    print()
    print(f"  [METRICS]  MTS cardinality comparison")
    print("-" * width)

    now_ms   = int(time.time() * 1000)
    LIVE     = "now"

    def load_metric_snap(date_str, label):
        if date_str.lower() == LIVE:
            print(f"  Fetching live metric snapshot for {label}...")
            snap = fetch_live_snapshot(verbose=False)
            ts   = datetime.now(timezone.utc).isoformat()
            print(f"  Live metric snapshot: {len(snap):,} metrics")
            return snap, ts
        else:
            snap, ts = db_get_snapshot_near_date(date_str)
            if snap:
                print(f"  Metric snapshot for {label}: {len(snap):,} metrics from {ts[:16]}")
            else:
                print(f"  No stored metric snapshot near '{date_str}' — fetching live...")
                snap = fetch_live_snapshot(verbose=False)
                ts   = datetime.now(timezone.utc).isoformat()
                print(f"  Live metric snapshot: {len(snap):,} metrics")
            return snap, ts

    msnap1, mts1 = load_metric_snap(date1, "baseline")
    msnap2, mts2 = load_metric_snap(date2, "compared")

    metric_deltas = compare_snapshots(msnap1, msnap2) if (msnap1 or msnap2) else []
    m_increased   = sorted([d for d in metric_deltas if d["delta"] >= metric_min_delta],
                           key=lambda x: -x["delta"])
    m_new         = [d for d in metric_deltas if d["mts1"] == 0 and d["mts2"] > 0]
    m_total1      = sum(d["mts1"] for d in metric_deltas)
    m_total2      = sum(d["mts2"] for d in metric_deltas)
    m_net         = m_total2 - m_total1
    m_pct         = round(m_net / m_total1 * 100, 1) if m_total1 > 0 else 0.0

    print()
    arrow = "+" if m_net >= 0 else "-"
    print(f"  Baseline  ({mts1[:16]}):  {m_total1:>10,} MTS   {estimate_cost(m_total1)}")
    print(f"  Compared  ({mts2[:16]}):  {m_total2:>10,} MTS   {estimate_cost(m_total2)}")
    print(f"  Net:                        {arrow}{abs(m_net):>9,} MTS  ({m_pct:+.1f}%)   "
          f"{estimate_cost(abs(m_net))} {'added' if m_net >= 0 else 'saved'}")
    print()

    if m_increased:
        print(f"  Top metric increases (>={metric_min_delta} MTS delta):")
        print(f"  {'Metric':<50} {'Baseline':>10} {'Current':>10} {'Delta':>10} {'Change':>8}  {'Source':<25} {'Token'}")
        print("  " + "-" * 118)
        for d in m_increased[:top_n]:
            pct_str  = f"+{d['pct_change']:.1f}%" if d["mts1"] > 0 else "NEW"
            base_str = f"{d['mts1']:,}" if d["mts1"] > 0 else "--"
            print(f"  {d['metric']:<50} {base_str:>10} {d['mts2']:>10,} {d['delta']:>+10,} "
                  f"{pct_str:>8}  {d['source']:<25} {d['token'] or '--'}")
        print()

        # Source breakdown
        by_src = defaultdict(lambda: {"metrics": 0, "delta": 0})
        for d in m_increased:
            by_src[d["source"]]["metrics"] += 1
            by_src[d["source"]]["delta"]   += d["delta"]
        print(f"  Metric source breakdown:")
        for src, info in sorted(by_src.items(), key=lambda x: -x[1]["delta"]):
            print(f"    {src:<30} {info['metrics']:>4} metrics   {info['delta']:>8,} MTS   {estimate_cost(info['delta'])}")
        print()
    elif msnap1 or msnap2:
        print(f"  No metric changes >= {metric_min_delta} MTS delta.\n")

    if m_new:
        print(f"  New metrics ({len(m_new)}): " +
              ", ".join(d["metric"] for d in sorted(m_new, key=lambda x: -x["mts2"])[:5]) +
              ("..." if len(m_new) > 5 else ""))
        print()

    # ── Traces section ────────────────────────────────────────────────────
    print("-" * width)
    print(f"  [TRACES]  APM span volume comparison  (env={env_label})")
    print("-" * width)
    print()

    window_ms = int(lookback_hours * 3600 * 1000)

    def load_trace_snap(date_str, label):
        if date_str.lower() == LIVE:
            print(f"  Fetching live trace snapshot for {label} (last {lookback_hours}h)...")
            snap, meta = fetch_trace_snapshot(now_ms - window_ms, now_ms, environment=environment)
            ts = datetime.now(timezone.utc).isoformat()
            print(f"  Live trace snapshot: {meta['sample_size']} traces, {len(snap)} services")
            if snap:
                db_save_trace_summary(ts, environment or "", snap)
            return snap, ts
        else:
            snap, ts = db_get_trace_snapshot_near_date(date_str, environment=environment)
            if snap:
                print(f"  Trace snapshot for {label}: {len(snap)} services from {ts[:16]}")
            else:
                print(f"  No stored trace snapshot near '{date_str}' — fetching live...")
                snap, meta = fetch_trace_snapshot(now_ms - window_ms, now_ms, environment=environment)
                ts = datetime.now(timezone.utc).isoformat()
                print(f"  Live trace snapshot: {meta['sample_size']} traces, {len(snap)} services")
                if snap:
                    db_save_trace_summary(ts, environment or "", snap)
            return snap, ts

    tsnap1, tts1 = load_trace_snap(date1, "baseline")
    tsnap2, tts2 = load_trace_snap(date2, "compared")

    # Build trace deltas
    t_deltas = []
    for svc in set(tsnap1) | set(tsnap2):
        s1 = tsnap1.get(svc, {"span_count": 0, "error_rate": 0.0})
        s2 = tsnap2.get(svc, {"span_count": 0, "error_rate": 0.0})
        delta = s2["span_count"] - s1["span_count"]
        pct   = round(delta / s1["span_count"] * 100, 1) if s1["span_count"] > 0 else (100.0 if s2["span_count"] > 0 else 0.0)
        t_deltas.append({
            "service":    svc,
            "spans1":     s1["span_count"],
            "spans2":     s2["span_count"],
            "delta":      delta,
            "pct":        pct,
            "err1":       s1["error_rate"] * 100,
            "err2":       s2["error_rate"] * 100,
            "err_delta":  round(s2["error_rate"] * 100 - s1["error_rate"] * 100, 2),
        })

    t_increased = sorted([d for d in t_deltas if d["delta"] >= trace_min_delta],
                         key=lambda x: -x["delta"])
    t_new       = [d for d in t_deltas if d["spans1"] == 0 and d["spans2"] > 0]
    t_total1    = sum(d["spans1"] for d in t_deltas)
    t_total2    = sum(d["spans2"] for d in t_deltas)
    t_net       = t_total2 - t_total1
    t_pct       = round(t_net / t_total1 * 100, 1) if t_total1 > 0 else 0.0

    print()
    tarrow = "+" if t_net >= 0 else "-"
    print(f"  Baseline  ({tts1[:16]}):  {t_total1:>8,} spans sampled")
    print(f"  Compared  ({tts2[:16]}):  {t_total2:>8,} spans sampled")
    print(f"  Net:                      {tarrow}{abs(t_net):>7,} spans  ({t_pct:+.1f}%)")
    print()

    if t_increased:
        print(f"  Top span increases (>={trace_min_delta} delta):")
        print(f"  {'Service':<35} {'Baseline':>9} {'Current':>9} {'Delta':>9} {'Change':>8}  {'ErrRate Now':>12}  {'Err Delta':>10}")
        print("  " + "-" * 100)
        for d in t_increased[:top_n]:
            pct_str  = f"+{d['pct']:.1f}%" if d["spans1"] > 0 else "NEW"
            base_str = f"{d['spans1']:,}" if d["spans1"] > 0 else "--"
            err_str  = f"{d['err_delta']:+.1f}pp" if d["err_delta"] != 0 else "--"
            print(f"  {d['service']:<35} {base_str:>9} {d['spans2']:>9,} {d['delta']:>+9,} "
                  f"{pct_str:>8}  {d['err2']:>10.1f}%  {err_str:>10}")
        print()
    elif tsnap1 or tsnap2:
        print(f"  No trace changes >= {trace_min_delta} span delta.\n")

    if t_new:
        print(f"  New services ({len(t_new)}): " +
              ", ".join(d["service"] for d in sorted(t_new, key=lambda x: -x["spans2"])[:5]) +
              ("..." if len(t_new) > 5 else ""))
        print()

    # ── Combined signal summary ───────────────────────────────────────────
    print("=" * width)
    print("  SIGNAL SUMMARY")
    print("=" * width)

    has_metric_spike = bool(m_increased or m_new)
    has_trace_spike  = bool(t_increased or t_new)

    if has_metric_spike and has_trace_spike:
        # Find services that appear in both
        metric_services = set()
        for d in m_increased:
            metric_services.update(d.get("services", []))
        trace_services = {d["service"] for d in t_increased + t_new}
        overlap = metric_services & trace_services
        print()
        print(f"  Both MTS and span volumes changed — likely a deployment or configuration change.")
        if overlap:
            print(f"  Services implicated in BOTH signals: {', '.join(sorted(overlap))}")
            print(f"  These are the highest-priority services to investigate.")
        print()
        print(f"  Metric change:  {m_net:+,} MTS  ({m_pct:+.1f}%)   {estimate_cost(abs(m_net))} {'added' if m_net >= 0 else 'saved'}")
        print(f"  Trace change:   {t_net:+,} spans sampled  ({t_pct:+.1f}%)")
    elif has_metric_spike and not has_trace_spike:
        print()
        print(f"  Only metric MTS changed — trace volume is stable.")
        print(f"  Likely cause: new dimensions or higher-cardinality labels introduced to an existing metric.")
        print(f"  Metric change: {m_net:+,} MTS  ({m_pct:+.1f}%)   {estimate_cost(abs(m_net))} {'added' if m_net >= 0 else 'saved'}")
    elif has_trace_spike and not has_metric_spike:
        print()
        print(f"  Only trace span volume changed — metric cardinality is stable.")
        print(f"  Likely cause: a service started generating more requests/operations, or sampling rate changed.")
        print(f"  Trace change:  {t_net:+,} spans sampled  ({t_pct:+.1f}%)")
    else:
        print()
        print(f"  No significant changes found above the configured thresholds.")
        print(f"  Metric threshold: {metric_min_delta} MTS  |  Trace threshold: {trace_min_delta} spans")
    print()


# ---------------------------------------------------------------------------
# Anomaly detection scan (baseline-relative)
# ---------------------------------------------------------------------------

def db_get_all_metrics_with_history(days=7, min_samples=3):
    """
    Return list of (metric, current_mts, avg_mts, num_samples) for metrics
    that have at least min_samples scan points within the last `days` days.
    current_mts = the most recent scan value.
    avg_mts     = average over the window (excluding the most recent point).
    """
    if not STATE_DB.exists():
        return []
    conn = db_connect()

    # For each metric: get all readings in the last N days
    rows = conn.execute(
        """SELECT metric, mts_count, scanned_at
           FROM scans
           WHERE realm=? AND scanned_at >= datetime('now', ?)
           ORDER BY metric, scanned_at DESC""",
        (REALM, f"-{days} days")
    ).fetchall()
    conn.close()

    from collections import OrderedDict
    by_metric = OrderedDict()
    for metric, mts, ts in rows:
        if metric not in by_metric:
            by_metric[metric] = []
        by_metric[metric].append((ts, mts))

    result = []
    for metric, readings in by_metric.items():
        if len(readings) < min_samples:
            continue
        # Most recent reading is current; rest form the baseline
        current_mts = readings[0][1]
        baseline_vals = [r[1] for r in readings[1:]]
        if not baseline_vals:
            continue
        avg = sum(baseline_vals) / len(baseline_vals)
        result.append((metric, current_mts, avg, len(readings)))

    return result


def cmd_anomaly_scan(top_n=20, ratio=None, days=7, min_samples=None):
    """
    Scan for metrics that are growing faster than their own historical baseline.
    Catches slow-burn explosions that haven't crossed static CRITICAL/HIGH thresholds yet.
    """
    if ratio is None:
        ratio = ANOMALY_RATIO
    if min_samples is None:
        min_samples = ANOMALY_MIN_SAMPLES

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"\nAnomaly Scan  (realm={REALM})  generated {now_str}")
    print(f"  Threshold: current MTS >= {ratio}x {days}-day average  |  min history points: {min_samples}\n")

    if not STATE_DB.exists():
        print("  No scan history found. Run 'scan' at least a few times to build a baseline.")
        return

    all_data = db_get_all_metrics_with_history(days=days, min_samples=min_samples)
    if not all_data:
        print(f"  No metrics have {min_samples}+ scan points in the last {days} days.")
        print(f"  Run 'scan' regularly (daily cron recommended) to build history.")
        return

    anomalies = []
    for metric, current, avg, samples in all_data:
        if avg <= 0:
            continue
        r = current / avg
        if r >= ratio:
            sev = severity(current)
            anomalies.append({
                "metric":   metric,
                "current":  current,
                "avg":      avg,
                "ratio":    round(r, 2),
                "samples":  samples,
                "severity": sev,
            })

    # Also find metrics currently below static thresholds but anomalous
    static_only  = [a for a in anomalies if a["severity"] == "LOW"]
    already_flagged = [a for a in anomalies if a["severity"] != "LOW"]

    anomalies.sort(key=lambda x: -x["ratio"])

    if not anomalies:
        print(f"  No anomalies detected across {len(all_data)} metrics with sufficient history.")
        print(f"  All metrics are within {ratio}x of their {days}-day average.")
        return

    print(f"  Checked {len(all_data)} metrics with {min_samples}+ history points.")
    print(f"  Found {len(anomalies)} anomaly/anomalies  "
          f"({len(already_flagged)} already above static thresholds, "
          f"{len(static_only)} below thresholds but growing abnormally)\n")

    # ── Anomalies below static thresholds (the real value-add) ────────────
    if static_only:
        print(f"  BELOW-THRESHOLD ANOMALIES  —  growing fast but not yet CRITICAL/HIGH")
        print(f"  These would be MISSED by a static threshold scan.")
        print(f"  {'Metric':<52} {'Current':>8} {'7d Avg':>8} {'Ratio':>7} {'Samples':>8} {'Severity'}")
        print("  " + "-" * 100)
        for a in sorted(static_only, key=lambda x: -x["ratio"])[:top_n]:
            sev_icon = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]"}.get(a["severity"], "[LOW]")
            print(f"  {a['metric']:<52} {a['current']:>8,} {a['avg']:>8,.0f} {a['ratio']:>6.1f}x "
                  f"{a['samples']:>8}  {sev_icon}")
        print()

    # ── Anomalies that are also above static thresholds ───────────────────
    if already_flagged:
        print(f"  ABOVE-THRESHOLD ANOMALIES  —  flagged by static scan AND growing abnormally fast")
        print(f"  {'Metric':<52} {'Current':>8} {'7d Avg':>8} {'Ratio':>7} {'Samples':>8} {'Severity'}")
        print("  " + "-" * 100)
        for a in sorted(already_flagged, key=lambda x: -x["ratio"])[:top_n]:
            sev_icon = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MEDIUM": "[MED]"}.get(a["severity"], "[LOW]")
            print(f"  {a['metric']:<52} {a['current']:>8,} {a['avg']:>8,.0f} {a['ratio']:>6.1f}x "
                  f"{a['samples']:>8}  {sev_icon}")
        print()

    # ── Summary ───────────────────────────────────────────────────────────
    if static_only:
        top_hidden = static_only[0]
        print(f"  Top hidden anomaly: '{top_hidden['metric']}'")
        print(f"    Current MTS: {top_hidden['current']:,}  |  7-day avg: {top_hidden['avg']:,.0f}  |  "
              f"Ratio: {top_hidden['ratio']}x  |  {estimate_cost(top_hidden['current'])}/mo")
        print(f"    Run: python3 cardinality_governance.py rollup --metric \"{top_hidden['metric']}\"")
    print()

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

    # compare
    p_compare = sub.add_parser("compare", help=(
        "Compare MTS counts between two dates to identify spike sources. "
        "Use 'now' as either date for a live snapshot. "
        "Falls back to stored scan history when available."
    ))
    p_compare.add_argument("--date1", required=True,
                           help="Baseline date: 'YYYY-MM-DD', 'YYYY-MM-DDTHH:MM', or 'now'")
    p_compare.add_argument("--date2", required=True,
                           help="Comparison date: 'YYYY-MM-DD', 'YYYY-MM-DDTHH:MM', or 'now'")
    p_compare.add_argument("--top", type=int, default=20,
                           help="Show top N metrics per section (default: 20)")
    p_compare.add_argument("--min-delta", type=int, default=100,
                           help="Minimum MTS change to include in output (default: 100)")
    p_compare.add_argument("--no-new", action="store_true",
                           help="Hide the 'new metrics' section")
    p_compare.add_argument("--show-dropped", action="store_true",
                           help="Also show metrics that decreased most")

    # trace-scan
    p_tscan = sub.add_parser("trace-scan", help=(
        "Snapshot current per-service trace/span volumes and save to history. "
        "Run regularly to build history for trace-compare."
    ))
    p_tscan.add_argument("--environment", "-e", default=None,
                         help="APM environment name (e.g. petclinicmbtest). Omit for all environments.")
    p_tscan.add_argument("--lookback", type=float, default=1.0,
                         help="Hours to look back for traces (default: 1)")
    p_tscan.add_argument("--no-save", action="store_true",
                         help="Print only, do not save snapshot to history")

    # trace-compare
    p_tcompare = sub.add_parser("trace-compare", help=(
        "Compare per-service trace/span volumes between two dates to identify TAPM spikes. "
        "Use 'now' for a live snapshot. Falls back to stored history when available."
    ))
    p_tcompare.add_argument("--date1", required=True,
                            help="Baseline: 'YYYY-MM-DD', 'YYYY-MM-DDTHH:MM', or 'now'")
    p_tcompare.add_argument("--date2", required=True,
                            help="Comparison: 'YYYY-MM-DD', 'YYYY-MM-DDTHH:MM', or 'now'")
    p_tcompare.add_argument("--environment", "-e", default=None,
                            help="APM environment name to filter (recommended)")
    p_tcompare.add_argument("--top", type=int, default=20,
                            help="Max services to show per section (default: 20)")
    p_tcompare.add_argument("--min-delta", type=int, default=10,
                            help="Minimum span delta to include (default: 10)")
    p_tcompare.add_argument("--lookback", type=float, default=1.0,
                            help="Hours per window for live snapshots (default: 1)")
    p_tcompare.add_argument("--no-new", action="store_true",
                            help="Hide new services section")
    p_tcompare.add_argument("--show-dropped", action="store_true",
                            help="Also show services with biggest span decreases")

    # usage-compare
    p_ucompare = sub.add_parser("usage-compare", help=(
        "Unified comparison — runs both metric MTS and trace span comparisons together. "
        "Useful for post-incident reviews to see the full picture across both signals."
    ))
    p_ucompare.add_argument("--date1", required=True,
                            help="Baseline: 'YYYY-MM-DD', 'YYYY-MM-DDTHH:MM', or 'now'")
    p_ucompare.add_argument("--date2", required=True,
                            help="Comparison: 'YYYY-MM-DD', 'YYYY-MM-DDTHH:MM', or 'now'")
    p_ucompare.add_argument("--environment", "-e", default=None,
                            help="APM environment for trace comparison (recommended)")
    p_ucompare.add_argument("--top", type=int, default=20,
                            help="Max rows per section (default: 20)")
    p_ucompare.add_argument("--metric-min-delta", type=int, default=100,
                            help="Minimum MTS delta for metric section (default: 100)")
    p_ucompare.add_argument("--trace-min-delta", type=int, default=10,
                            help="Minimum span delta for trace section (default: 10)")
    p_ucompare.add_argument("--lookback", type=float, default=1.0,
                            help="Hours per window for live trace snapshots (default: 1)")
    p_ucompare.add_argument("--show-dropped", action="store_true",
                            help="Show metrics/services that decreased most")

    # anomaly-scan
    p_ascan = sub.add_parser("anomaly-scan", help=(
        "Scan for metrics growing faster than their own 7-day historical baseline. "
        "Catches slow-burn cardinality explosions that haven't crossed static thresholds yet."
    ))
    p_ascan.add_argument("--top", type=int, default=20,
                         help="Show top N anomalies (default: 20)")
    p_ascan.add_argument("--ratio", type=float, default=ANOMALY_RATIO,
                         help=f"Flag if current MTS exceeds N times 7-day avg (default: {ANOMALY_RATIO})")
    p_ascan.add_argument("--days", type=int, default=7,
                         help="Baseline window in days (default: 7)")
    p_ascan.add_argument("--min-samples", type=int, default=ANOMALY_MIN_SAMPLES,
                         help=f"Minimum history points required (default: {ANOMALY_MIN_SAMPLES})")

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
            anomaly_tag = f" [ANOMALY {f['baseline_ratio']}x]" if f.get("anomaly") else ""
            worst = f"{f['worst_dim']} ({f['worst_dim_info']['unique_values']:,})" if f["worst_dim"] else "—"
            print(f"{i:<5} {f['metric']:<45} {f['mts_count']:>8,} {trend_str:<14} {sev_icon+f['severity']:<14} {f['instr_source']:<28} {worst}{anomaly_tag}")

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

    elif args.command == "compare":
        cmd_compare(
            date1        = args.date1,
            date2        = args.date2,
            top_n        = args.top,
            min_delta    = args.min_delta,
            show_new     = not args.no_new,
            show_dropped = args.show_dropped,
        )

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

    elif args.command == "trace-scan":
        cmd_scan_traces(
            environment   = args.environment,
            lookback_hours = args.lookback,
            save          = not args.no_save,
        )

    elif args.command == "trace-compare":
        cmd_compare_traces(
            date1          = args.date1,
            date2          = args.date2,
            environment    = args.environment,
            top_n          = args.top,
            min_delta      = args.min_delta,
            show_new       = not args.no_new,
            show_dropped   = args.show_dropped,
            lookback_hours = args.lookback,
        )

    elif args.command == "usage-compare":
        cmd_usage_compare(
            date1             = args.date1,
            date2             = args.date2,
            environment       = args.environment,
            top_n             = args.top,
            metric_min_delta  = args.metric_min_delta,
            trace_min_delta   = args.trace_min_delta,
            lookback_hours    = args.lookback,
            show_dropped      = args.show_dropped,
        )

    elif args.command == "anomaly-scan":
        cmd_anomaly_scan(
            top_n       = args.top,
            ratio       = args.ratio,
            days        = args.days,
            min_samples = args.min_samples,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
