# o11y-usage-governance

Observability usage governance for Splunk Observability Cloud. Identifies the source of metric cardinality explosions and trace volume spikes, attributes cost to services and teams, generates ready-to-apply fixes, and detects anomalies before they become billing surprises.

## What it covers

| Signal | Problem it solves |
|--------|-------------------|
| **Metrics (MTS)** | Cardinality explosions — unbounded dimensions driving unexpected MTS growth and billing overages |
| **Traces (APM)** | Span volume spikes — identifying which service suddenly started sending significantly more traces |

Both signals can be compared between any two dates to answer: _"what changed, and which service caused it?"_

## Why it matters

- A single metric with an unbounded dimension (UUID, IP, user ID) can silently generate millions of MTS
- A misconfigured or newly deployed service can double an org's trace ingest overnight
- Static thresholds miss slow-burn growth — a metric at 800 MTS growing 4x/week hits 50,000 MTS within two weeks
- None of this is visible without tooling — this tool closes that gap with continuous scanning, baseline-relative anomaly detection, trend tracking, and cost attribution

---

## Setup

```bash
git clone https://github.com/mqbui1/o11y-usage-governance
cd o11y-usage-governance

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export SPLUNK_ACCESS_TOKEN=<your-api-token>
export SPLUNK_REALM=us1              # us0, us1, us2, eu0, ap0, etc.
export SPLUNK_INGEST_TOKEN=<token>   # optional — needed for watch mode events only
```

For AI remediation (optional — Claude via AWS Bedrock):
```bash
export AWS_DEFAULT_REGION=us-west-2
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
export AWS_SESSION_TOKEN=<token>     # if using temporary credentials
```

---

## Commands

### Metrics

| Command | Description |
|---------|-------------|
| `scan` | Quick ranked table of top cardinality offenders, with anomaly flags |
| `anomaly-scan` | Find metrics growing faster than their own 7-day baseline |
| `report` | Full Markdown or HTML report with AI remediation, saved to `reports/` |
| `compare` | Compare MTS counts between two dates — find what drove a spike |
| `drilldown` | Full blast radius for a specific dimension across all metrics |
| `resolve` | Manually mark a metric as remediated after applying a fix |
| `watch` | Continuous polling — emits Splunk events on new explosions |
| `rollup` | Deep-dive on a single metric with SignalFlow rollup suggestions |
| `ignore` | Exclude a metric or glob pattern from future scans |
| `unignore` | Remove a pattern from the ignore list |
| `ignored` | List all active ignore patterns |
| `history` | Show scan history — total MTS, cost, severity trend over time |

### Traces (APM)

| Command | Description |
|---------|-------------|
| `trace-scan` | Snapshot current per-service span volumes and save to history |
| `trace-compare` | Compare span volumes between two dates — identify which service spiked |

### Cross-signal

| Command | Description |
|---------|-------------|
| `usage-compare` | Unified metrics + traces comparison in one output — for post-incident reviews |

---

## Quick start

### Metrics

```bash
# Scan — top 20 metrics ranked by MTS, with anomaly flags on fast-growing metrics
python3 cardinality_governance.py scan

# Scan all metrics including low severity
python3 cardinality_governance.py scan --verbose

# Anomaly scan — find metrics growing faster than their own 7-day average
python3 cardinality_governance.py anomaly-scan
python3 cardinality_governance.py anomaly-scan --ratio 1.5   # more sensitive

# Full report (Markdown)
python3 cardinality_governance.py report

# HTML report — self-contained, opens in browser
python3 cardinality_governance.py report --format html --no-ai

# Compare MTS between two dates
python3 cardinality_governance.py compare --date1 2026-04-01 --date2 now
python3 cardinality_governance.py compare --date1 2026-03-20 --date2 2026-04-01 --min-delta 50

# Full blast radius for a dimension before applying a fix
python3 cardinality_governance.py drilldown --dimension server.address

# Mark a metric resolved after deploying the fix
python3 cardinality_governance.py resolve --metric http.client.request.duration_bucket \
  --note "applied delete_key(server.address) in collector v1.2"

# Suppress Splunk internals from reports
python3 cardinality_governance.py ignore "sf.org.*" --reason "Splunk internal"
python3 cardinality_governance.py ignore "otelcol_*" --reason "Collector telemetry"

# Show scan history
python3 cardinality_governance.py history
```

### Traces

```bash
# Snapshot current per-service span volumes (saves to history)
python3 cardinality_governance.py trace-scan --environment myenv

# Compare span volumes: stored date vs live
python3 cardinality_governance.py trace-compare \
  --date1 2026-04-01 --date2 now --environment myenv

# Lower threshold; show services that dropped too
python3 cardinality_governance.py trace-compare \
  --date1 2026-04-01 --date2 now --environment myenv \
  --min-delta 5 --show-dropped
```

### Unified

```bash
# Post-incident review: both signals in one command
python3 cardinality_governance.py usage-compare \
  --date1 2026-04-01 --date2 now --environment myenv
```

---

## `scan` — metric cardinality scan

```bash
python3 cardinality_governance.py scan [--top N] [--verbose]
```

Fetches all metrics, counts MTS per metric, ranks by highest cardinality. Metrics growing faster than their 7-day baseline are tagged `[ANOMALY Nx]`.

```
Rank  Metric                               MTS   Trend          Severity    Source                Worst Dimension
1     http.client.request.duration_bucket  1,215 GROWING(+30%)  HIGH        HTTP Instrumentation  server.address (21) [ANOMALY 4.0x]
2     http.server.request.duration_bucket    810 STABLE         MEDIUM      HTTP Instrumentation  http.route (24)
```

| Column | Description |
|--------|-------------|
| MTS | Total metric time series |
| Trend | GROWING / FALLING / STABLE / NEW vs last scan |
| Severity | CRITICAL (>=10k) / HIGH (>=1k) / MEDIUM (>=500) |
| Source | Inferred instrumentation origin |
| Worst Dimension | Highest-cardinality dimension and unique value count |
| `[ANOMALY Nx]` | Current MTS is N× the 7-day average — growing abnormally fast |

---

## `anomaly-scan` — baseline-relative detection

```bash
python3 cardinality_governance.py anomaly-scan [--ratio 2.0] [--days 7] [--min-samples 3]
```

Flags metrics growing faster than their own historical baseline — catches slow-burn explosions that haven't crossed static thresholds yet.

```
Anomaly Scan  (realm=us1)
  Threshold: current MTS >= 2.0x 7-day average  |  min history points: 3

  Checked 50 metrics with 3+ history points.
  Found 5 anomalies  (2 above static thresholds, 3 below thresholds but growing abnormally)

  BELOW-THRESHOLD ANOMALIES  —  would be MISSED by static threshold scan
  Metric                                             Current   7d Avg   Ratio  Samples  Severity
  http.client.request.duration_bucket                    480      120    4.0x        8  [MED]
  db.client.connections.wait_time_bucket                 240       60    4.0x        5  [LOW]

  ABOVE-THRESHOLD ANOMALIES  —  flagged by static scan AND growing abnormally
  Metric                                             Current   7d Avg   Ratio  Samples  Severity
  k8s.pod.phase                                        1,500      400    3.8x        7  [HIGH]

  Top hidden anomaly: 'http.client.request.duration_bucket'
    Current MTS: 480  |  7-day avg: 120  |  Ratio: 4.0x  |  ~$0.96/mo
    Run: python3 cardinality_governance.py rollup --metric "http.client.request.duration_bucket"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--ratio` | 2.0 | Flag if current MTS >= N × baseline avg |
| `--days` | 7 | Baseline window in days |
| `--min-samples` | 3 | Minimum history points required |
| `--top` | 20 | Max anomalies per section |

```bash
export ANOMALY_RATIO=1.5        # global default override
export ANOMALY_MIN_SAMPLES=2
```

---

## `compare` — metric MTS spike comparison

```bash
python3 cardinality_governance.py compare --date1 DATE --date2 DATE [options]
```

Compares MTS counts between two snapshots. Uses stored scan history when available; fetches live for `now`.

```
Baseline  (2026-04-01T08:00):       4,283 MTS   ~$8.57/mo
Compared  (2026-04-06T16:29):       8,493 MTS   ~$16.99/mo
Net change:               +    4,210 MTS  (+98.3%)   ~$8.42/mo added

TOP MTS INCREASES  (>=100 delta)
Rank  Metric                                Baseline  Current    Delta   Change  Source           Services / Token
1     http.server.request.duration_bucket        120      480     +360  +200.0%  OTel SDK (app)   api-gateway [petclinic-INGEST]

Source breakdown:
  OTel SDK (app)       8 metrics    2,840 MTS   ~$5.68/mo
  OTel Collector       3 metrics      890 MTS   ~$1.78/mo

Token breakdown:
  petclinic-INGEST     8 metrics    2,840 MTS added
```

| Flag | Default | Description |
|------|---------|-------------|
| `--date1` / `--date2` | required | `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`, or `now` |
| `--min-delta` | 100 | Minimum MTS change to include |
| `--top` | 20 | Max rows per section |
| `--show-dropped` | off | Show metrics that decreased |
| `--no-new` | off | Hide new metrics section |

**Tip:** Run `scan` on a schedule to build history — `compare` then diffs any two stored dates instantly.

---

## `trace-scan` — APM span volume snapshot

```bash
python3 cardinality_governance.py trace-scan [--environment ENV] [--lookback 1.0]
```

Samples up to 200 traces in the lookback window and aggregates per-service span counts. Saves to history for later comparison.

```
Trace Scan  (realm=us1)  env=myenv  last 1.0h

  Sample: 200 traces sampled

  Service                    Spans   Traces   Errors    Err%
  -----------------------------------------------------------
  api-gateway                  221      187        0    0.0%
  customers-service            211        1        0    0.0%
  mysql:petclinic              137        0        0    0.0%

  Snapshot saved to cardinality_state.db
```

| Flag | Default | Description |
|------|---------|-------------|
| `--environment` / `-e` | all | APM environment name |
| `--lookback` | 1.0 | Hours to sample |
| `--no-save` | off | Print only, don't persist |

---

## `trace-compare` — APM span volume spike comparison

```bash
python3 cardinality_governance.py trace-compare --date1 DATE --date2 DATE [options]
```

Compares per-service span volumes between two snapshots, including error rate changes.

```
Trace Spike Comparison  (realm=us1)  env=myenv

  Baseline  (2026-04-01T08:00):   312 spans sampled
  Compared  (2026-04-06T16:50):   673 spans sampled
  Net change:               +   361 spans  (+115.7%)

  TOP SPAN INCREASES
  Service               Baseline  Current    Delta   Change  ErrRate Baseline  ErrRate Now  Err Delta
  api-gateway                 85      221     +136  +160.0%              0.0%         0.0%     +0.0pp
  customers-service           63      211     +148  +234.9%              2.1%         0.0%     -2.1pp
```

Span counts are from a sampled window — relative changes are reliable; use deltas as indicators, not absolute volume.

| Flag | Default | Description |
|------|---------|-------------|
| `--date1` / `--date2` | required | `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`, or `now` |
| `--environment` / `-e` | all | APM environment — strongly recommended |
| `--min-delta` | 10 | Minimum span delta |
| `--top` | 20 | Max services per section |
| `--lookback` | 1.0 | Window size (hours) for live snapshots |
| `--show-dropped` | off | Show services with biggest decreases |
| `--no-new` | off | Hide new services section |

---

## `usage-compare` — unified metrics + traces

```bash
python3 cardinality_governance.py usage-compare --date1 DATE --date2 DATE [options]
```

Runs metric MTS comparison and trace span comparison together, then produces a **signal summary** that cross-references both — highlighting services that appear in both signals (highest-priority investigation targets).

```
========================================================================================================================
  USAGE COMPARE  |  realm=us1  |  env=myenv  |  2026-04-06 17:05 UTC
  Baseline: 2026-04-01   vs   Compared: now
========================================================================================================================

  [METRICS]  MTS cardinality comparison
  -------
  Baseline  (2026-04-01):   4,283 MTS   ~$8.57/mo
  Compared  (now):          8,493 MTS   ~$16.99/mo
  Net:       +4,210 MTS  (+98.3%)   ~$8.42/mo added

  Top metric increases ...
  Source breakdown ...

  [TRACES]  APM span volume comparison  (env=myenv)
  -------
  Baseline  (2026-04-01):   312 spans sampled
  Compared  (now):          673 spans sampled
  Net:       +361 spans  (+115.7%)

  Top span increases ...

========================================================================================================================
  SIGNAL SUMMARY
========================================================================================================================

  Both MTS and span volumes changed — likely a deployment or configuration change.
  Services implicated in BOTH signals: api-gateway, customers-service
  These are the highest-priority services to investigate.

  Metric change:  +4,210 MTS  (+98.3%)   ~$8.42/mo added
  Trace change:   +361 spans sampled  (+115.7%)
```

Signal summary interpretations:
- **Both changed** → likely a deployment; services in both signals are highest priority
- **Only metrics changed** → new dimensions or higher-cardinality labels; no traffic increase
- **Only traces changed** → service traffic increase or sampling rate change; no new metric dimensions

| Flag | Default | Description |
|------|---------|-------------|
| `--date1` / `--date2` | required | `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`, or `now` |
| `--environment` / `-e` | all | APM environment for trace section |
| `--metric-min-delta` | 100 | Minimum MTS change for metric section |
| `--trace-min-delta` | 10 | Minimum span delta for trace section |
| `--top` | 20 | Max rows per section |
| `--lookback` | 1.0 | Hours per window for live trace snapshots |
| `--show-dropped` | off | Show decreases |

---

## Metric features reference

### Severity thresholds

| Severity | MTS count | Action |
|----------|-----------|--------|
| CRITICAL | >= 10,000 | Immediate — significant billing impact |
| HIGH | >= 1,000 | Investigate and plan remediation |
| MEDIUM | >= 500 | Monitor, address in next sprint |

### Instrumentation source detection

| Source | Metric prefix examples |
|--------|----------------------|
| OTel Collector | `otelcol_*` |
| JVM | `jvm.*`, `process.runtime.jvm.*` |
| Kubernetes | `k8s.*` |
| Host / OS | `system.*`, `process.*` |
| HTTP | `http.*` |
| Database | `db.*`, `mysql.*`, `redis.*` |
| Messaging | `kafka.*`, `messaging.*` |
| Cloud | `aws.*`, `azure.*`, `gcp.*` |
| Splunk internal | `sf.*`, `splunk.*` |

### Anti-pattern detection

| Pattern | Example |
|---------|---------|
| UUID | `550e8400-e29b-41d4-a716-446655440000` |
| IP address | `10.42.2.32` |
| Timestamp / epoch | `1712345678901` |
| MD5 / SHA1 hash | `d41d8cd98f00b204e9800998ecf8427e` |
| Very long string | Any value > 100 characters |

### Fix suggestion generator

Every duplicate group in the report includes ready-to-paste OTel Collector processor configs.

**Drop the dimension** (eliminates the cardinality explosion):
```yaml
processors:
  transform/drop_server_address:
    metric_statements:
      - context: datapoint
        statements:
          - delete_key(attributes, "server.address")
        include:
          match_type: strict
          metric_names:
            - 'http.client.request.duration_bucket'
            - 'http.client.request.duration_count'
            - 'http.client.request.duration_sum'
service:
  pipelines:
    metrics:
      processors: [transform/drop_server_address, ...]
```

**Hash instead of drop** (preserves groupability, eliminates explosion):
```yaml
processors:
  transform/hash_server_address:
    metric_statements:
      - context: datapoint
        statements:
          - set(attributes["server.address"], SHA256(attributes["server.address"]))
        include:
          match_type: strict
          metric_names: [...]
```

### Dimension drill-down

Full blast radius for a dimension — including low-MTS metrics below severity thresholds:

```bash
python3 cardinality_governance.py drilldown --dimension server.address
```

Useful before applying a fix to confirm the generated YAML covers every affected metric.

### Remediation tracking

Auto-detected when MTS drops >50% vs historical peak. Manual resolve:

```bash
python3 cardinality_governance.py resolve \
  --metric http.client.request.duration_bucket \
  --note "applied delete_key(server.address) in collector v1.2"
```

Resolved findings appear at the top of the next report confirming the fix worked.

### Cost estimation

Default rate: **$0.002/MTS/month**. Override:

```bash
export MTS_COST_PER_MONTH=0.005
```

Appears in report header, Top Offenders table, per-service scorecard, `compare`, and `usage-compare` output. Cumulative savings shown as fixes are applied.

### False positive suppression

```bash
python3 cardinality_governance.py ignore "sf.org.*" --reason "Splunk internal"
python3 cardinality_governance.py ignore "otelcol_*" --reason "Collector telemetry"
python3 cardinality_governance.py ignored
python3 cardinality_governance.py unignore "sf.org.*"
```

Uses `fnmatch` glob syntax. Stored in `cardinality_state.db`.

### Scan history

```bash
python3 cardinality_governance.py history
```

```
Date                    Metrics  Total MTS  Est Cost/Mo   CRIT  HIGH  MED  Ignored
2026-04-01 08:00          1,038     12,450     ~$24.90      8     5    3       12
2026-04-02 08:00          1,041     13,200     ~$26.40     10     5    3       12
2026-04-03 08:00          1,041      9,800     ~$19.60      6     4    3       12

Trend over 7 scans: DOWN 21.3%  (-2,650 MTS / ~-$5.30/mo)
```

### HTML report

```bash
python3 cardinality_governance.py report --format html --no-ai
```

Self-contained `.html` file with six sortable-table tabs: Top Offenders, Service Scorecard, Duplicate Groups (with collapsible fix YAML), Resolved, Detailed Findings, Ignored.

### Watch mode

```bash
python3 cardinality_governance.py watch --interval 300 --threshold 5000
```

| Event | Trigger |
|-------|---------|
| `cardinality.explosion.detected` | Metric crosses threshold for the first time |
| `cardinality.explosion.growing` | Existing high-cardinality metric grew >50% |

---

## State and persistence

All state stored in `cardinality_state.db` (SQLite, auto-created):

| Table | Contents |
|-------|----------|
| `scans` | Per-metric MTS per run — powers trend, `compare`, `anomaly-scan` |
| `scan_summaries` | Per-run totals — powers `history` |
| `remediations` | Resolved findings with peak/current MTS |
| `ignored` | Active ignore patterns |
| `trace_snapshots` | Per-service span counts — powers `trace-compare`, `usage-compare` |

---

## Recommended cron

```cron
# Daily metric scan — builds history for compare, anomaly-scan, trend tracking
0 8 * * *  cd /path/to/o11y-usage-governance && \
           SPLUNK_ACCESS_TOKEN=... SPLUNK_REALM=us1 \
           python3 cardinality_governance.py scan --top 100

# Hourly trace snapshot — builds history for trace-compare and usage-compare
0 * * * *  cd /path/to/o11y-usage-governance && \
           SPLUNK_ACCESS_TOKEN=... SPLUNK_REALM=us1 \
           python3 cardinality_governance.py trace-scan --environment myenv
```

---

## Requirements

- Python 3.9+
- `requests` — Splunk API calls
- `boto3` — optional, only needed for AI remediation (Claude via AWS Bedrock)
