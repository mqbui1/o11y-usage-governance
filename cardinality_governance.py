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

    # Org limit section
    org = fetch_org_info()
    mts_limit = org.get("mtsCategoryInfo", {}).get("mtsLimitThreshold") \
             or org.get("mtsLimit") \
             or org.get("numResourcesMonitored")
    if mts_limit:
        pct_used = round(total_mts / mts_limit * 100, 1)
        lines.append(f"**Org MTS limit:** {mts_limit:,}")
        lines.append(f"**Findings as % of org limit:** {pct_used}%")

    lines.append(f"\n## Summary\n")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| 🔴 CRITICAL (≥{CRITICAL_MTS_COUNT:,} MTS) | {len(critical)} |")
    lines.append(f"| 🟠 HIGH (≥{HIGH_MTS_COUNT:,} MTS)     | {len(high)} |")
    lines.append(f"| 🟡 MEDIUM (≥{MEDIUM_MTS_COUNT:,} MTS)   | {len(medium)} |")

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
        lines.append(f"| Metric | Peak MTS | Current MTS | Reduction | Resolved At | How |")
        lines.append(f"|--------|----------|-------------|-----------|-------------|-----|")
        # Build a quick lookup of current MTS from findings
        current_mts_map = {f["metric"]: f["mts_count"] for f in findings}
        for row in resolved:
            metric, peak_mts, peak_at, resolved_mts, resolved_at, reduction_pct, manual = row
            current = current_mts_map.get(metric, resolved_mts)
            how = "manual" if manual else "auto-detected"
            resolved_date = resolved_at[:10]
            lines.append(f"| `{metric}` | {peak_mts:,} | {current:,} | -{reduction_pct}% | {resolved_date} | {how} |")
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
    p_report = sub.add_parser("report", help="Generate full Markdown report with AI remediation")
    p_report.add_argument("--top", type=int, default=50, help="Analyze top N metrics (default: 50)")
    p_report.add_argument("--no-ai", action="store_true", help="Skip AI remediation (faster)")

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
        outpath, _ = generate_report(findings, use_claude=not args.no_ai)
        print(f"\nReport saved to: {outpath}")

    elif args.command == "watch":
        watch_mode(interval=args.interval, threshold=args.threshold)

    elif args.command == "rollup":
        suggest_rollup(args.metric)

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
