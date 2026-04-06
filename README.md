# o11y-usage-governance

Observability usage governance for Splunk Observability Cloud. Identifies the source of metric cardinality explosions and trace volume spikes, attributes cost to services and teams, and generates ready-to-apply fixes.

## What it covers

| Signal | Problem it solves |
|--------|-------------------|
| **Metrics (MTS)** | Cardinality explosions — unbounded dimensions driving unexpected MTS growth and billing overages |
| **Traces (APM)** | Span volume spikes — identifying which service suddenly started sending significantly more traces |

Both can be compared between any two dates to quickly answer: _"what changed, and which service caused it?"_

## Why it matters

- A single metric with an unbounded dimension (UUID, IP address, user ID) can silently generate millions of MTS
- A misconfigured or newly deployed service can double an org's trace ingest overnight
- Neither problem is visible without tooling — this closes that gap with continuous scanning, trend tracking, and cost attribution

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
| `scan` | Quick ranked table of top cardinality offenders |
| `report` | Full Markdown or HTML report with AI remediation, saved to `reports/` |
| `watch` | Continuous polling — emits Splunk events on new explosions |
| `rollup` | Deep-dive on a single metric with SignalFlow rollup suggestions |
| `compare` | Compare MTS counts between two dates — find what drove a spike |
| `drilldown` | Full blast radius for a specific dimension across all metrics |
| `resolve` | Manually mark a metric as remediated after applying a fix |
| `ignore` | Exclude a metric or glob pattern from future scans |
| `unignore` | Remove a pattern from the ignore list |
| `ignored` | List all active ignore patterns |
| `history` | Show scan history — total MTS, cost, severity trend over time |

### Traces (APM)

| Command | Description |
|---------|-------------|
| `trace-scan` | Snapshot current per-service span volumes and save to history |
| `trace-compare` | Compare span volumes between two dates — identify which service spiked |

---

## Metrics: quick start

```bash
# Scan the org — top 20 metrics ranked by MTS
python3 cardinality_governance.py scan

# Show all metrics including low severity
python3 cardinality_governance.py scan --verbose

# Full report with AI remediation (Markdown)
python3 cardinality_governance.py report

# HTML report — self-contained, opens in browser
python3 cardinality_governance.py report --format html --no-ai

# Compare metric MTS between two dates
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

### `scan` output

```
Rank  Metric                               MTS   Trend            Severity     Source                Worst Dimension
1     http.client.request.duration_bucket  1,215 GROWING(+30%)    HIGH         HTTP Instrumentation  server.address (21 values)
2     http.server.request.duration_bucket    810 STABLE           MEDIUM       HTTP Instrumentation  http.route (24 values)
```

| Column | Description |
|--------|-------------|
| MTS | Total metric time series for this metric |
| Trend | Change vs last scan: GROWING / FALLING / STABLE / NEW |
| Severity | CRITICAL (>=10k MTS) / HIGH (>=1k) / MEDIUM (>=500) |
| Source | Inferred instrumentation origin |
| Worst Dimension | Highest-cardinality dimension and unique value count |

### `compare` output

Compares metric MTS between two snapshots. Uses stored scan history when available; fetches live data for `now` or when no stored snapshot exists near the given date.

```
Baseline  (2026-04-01T08:00):       4,283 MTS   ~$8.57/mo
Compared  (2026-04-06T16:29):       8,493 MTS   ~$16.99/mo
Net change:               +    4,210 MTS  (+98.3%)   ~$8.42/mo added

TOP MTS INCREASES  (>=100 MTS delta)  --  12 metric(s)
Rank  Metric                                Baseline  Current    Delta   Change  Source           Services / Token
1     http.server.request.duration_bucket        120      480     +360  +200.0%  OTel SDK (app)   api-gateway [petclinic-INGEST]
2     http.client.request.duration_bucket         80      320     +240  +200.0%  OTel SDK (app)   visits-service [petclinic-INGEST]

Source breakdown:
  OTel SDK (app)       8 metrics    2,840 MTS added    ~$5.68/mo
  OTel Collector       3 metrics      890 MTS added    ~$1.78/mo

Token breakdown:
  petclinic-INGEST     8 metrics    2,840 MTS added
```

`compare` options: `--date1`, `--date2` (required), `--top` (default 20), `--min-delta` (default 100), `--show-dropped`, `--no-new`

**Tip:** Run `scan` on a schedule to build history, then `compare` diffs any two stored dates instantly without re-fetching.

---

## Traces: quick start

```bash
# Snapshot current per-service span volumes (saves to history)
python3 cardinality_governance.py trace-scan --environment petclinicmbtest

# Compare span volumes: stored date vs live
python3 cardinality_governance.py trace-compare \
  --date1 2026-04-01 --date2 now --environment petclinicmbtest

# Compare two stored dates
python3 cardinality_governance.py trace-compare \
  --date1 2026-03-20 --date2 2026-04-01 --environment petclinicmbtest

# Lower threshold; show services that dropped too
python3 cardinality_governance.py trace-compare \
  --date1 2026-04-01 --date2 now --environment petclinicmbtest \
  --min-delta 5 --show-dropped
```

### `trace-scan` output

```
Trace Scan  (realm=us1)  env=petclinicmbtest  last 1.0h

  Sample: 200 traces sampled over 1.0h

  Service                    Spans   Traces   Errors    Err%
  -----------------------------------------------------------
  api-gateway                  221      187        0    0.0%
  customers-service            211        1        0    0.0%
  mysql:petclinic              137        0        0    0.0%
  vets-service                  57        1        0    0.0%

  Snapshot saved to cardinality_state.db at 2026-04-06T16:49
```

### `trace-compare` output

```
Trace Spike Comparison  (realm=us1)  env=petclinicmbtest

  Baseline  (2026-04-01T08:00):   312 spans sampled
  Compared  (2026-04-06T16:50):   673 spans sampled
  Net change:               +   361 spans  (+115.7%)

  TOP SPAN INCREASES  (>=10 span delta)  --  3 service(s)
  Service               Baseline  Current    Delta   Change  ErrRate Baseline  ErrRate Now  Err Delta
  api-gateway                 85      221     +136  +160.0%              0.0%         0.0%     +0.0pp
  customers-service           63      211     +148  +234.9%              2.1%         0.0%     -2.1pp
  mysql:petclinic             40      137      +97  +242.5%              0.0%         0.0%     +0.0pp
```

Span counts are from a 200-trace sample — relative changes between services are reliable; use deltas as indicators, not absolute volume.

### `trace-compare` options

| Flag | Default | Description |
|------|---------|-------------|
| `--date1` / `--date2` | required | `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`, or `now` |
| `--environment` / `-e` | all | APM environment name — strongly recommended |
| `--min-delta` | 10 | Minimum span delta to include |
| `--top` | 20 | Max services per section |
| `--lookback` | 1.0 | Hours per window for live snapshots |
| `--show-dropped` | off | Show services with biggest span decreases |
| `--no-new` | off | Hide new services section |

**Tip:** Run `trace-scan` hourly via cron to build history:
```cron
0 * * * *  cd /path/to/o11y-usage-governance && \
           SPLUNK_ACCESS_TOKEN=... \
           python3 cardinality_governance.py trace-scan --environment myenv
```

---

## Metrics: detailed feature reference

### Severity thresholds

| Severity | MTS count | Action |
|----------|-----------|--------|
| CRITICAL | >= 10,000 | Immediate — significant billing impact |
| HIGH | >= 1,000 | Investigate and plan remediation |
| MEDIUM | >= 500 | Monitor, address in next sprint |

### Instrumentation source detection

Automatically identified from metric name prefix and dimensions:

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

Dimensions are checked for values that indicate unbounded cardinality:

| Pattern | Example |
|---------|---------|
| UUID | `550e8400-e29b-41d4-a716-446655440000` |
| IP address | `10.42.2.32` |
| Timestamp / epoch | `1712345678901` |
| MD5 / SHA1 hash | `d41d8cd98f00b204e9800998ecf8427e` |
| Very long string | Any value > 100 characters |

### Fix suggestion generator

Every duplicate group in the report includes two ready-to-paste OTel Collector processor configs.

**Option 1 — Drop the dimension** (eliminates the cardinality explosion):
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

**Option 2 — Hash instead of drop** (preserves groupability without cardinality explosion):
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

Each processor is scoped to only the affected metrics via `include.metric_names`.

### Dimension drill-down

Full blast radius for a dimension — including low-MTS metrics that didn't cross severity thresholds:

```bash
python3 cardinality_governance.py drilldown --dimension server.address
```

```
Dimension drill-down: `server.address`

  16 metrics carry this dimension
  Combined MTS: 861  |  Est. cost: ~$1.72/mo
  Max unique values: 21  |  Anti-pattern: IP address

Rank  Metric                               MTS   Unique Values  Services
1     http.client.request.duration_bucket  500              11  api-gateway
2     http.client.request.duration_min      81              21  api-gateway, admin-server
...

FIX: Drop `server.address` from all 16 metrics  [YAML follows]
```

### Remediation tracking

**Auto-detection:** each scan checks whether any metric's MTS dropped >50% vs its historical peak and marks it resolved automatically.

**Manual resolve:**
```bash
python3 cardinality_governance.py resolve \
  --metric http.client.request.duration_bucket \
  --note "applied delete_key(server.address) in collector v1.2"
```

Resolved findings appear at the top of the next report confirming the fix worked.

### Cost estimation

Default rate: **$0.002/MTS/month**. Override to match your contract:

```bash
export MTS_COST_PER_MONTH=0.005
```

Cost appears in the report header, Top Offenders table, per-service scorecard, and `compare` output. The report header shows cumulative savings across all resolved metrics.

### False positive suppression

```bash
python3 cardinality_governance.py ignore "sf.org.*" --reason "Splunk internal"
python3 cardinality_governance.py ignore "otelcol_*" --reason "Collector telemetry"
python3 cardinality_governance.py ignored
python3 cardinality_governance.py unignore "sf.org.*"
```

Patterns use `fnmatch` glob syntax (`*` matches any characters). Stored in `cardinality_state.db`.

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

Generates a self-contained `.html` file in `reports/` — no external dependencies, shareable as a single attachment. Six tabs: Top Offenders, Service Scorecard, Duplicate Groups (with collapsible fix YAML), Resolved, Detailed Findings, Ignored. All tables are sortable.

### Watch mode

```bash
python3 cardinality_governance.py watch --interval 300 --threshold 5000
```

Polls on an interval and emits custom events to Splunk:

| Event | Trigger |
|-------|---------|
| `cardinality.explosion.detected` | Metric crosses threshold for the first time |
| `cardinality.explosion.growing` | Existing high-cardinality metric grew >50% |

---

## State and persistence

All state is stored in `cardinality_state.db` (SQLite, created automatically):

| Table | Contents |
|-------|----------|
| `scans` | Per-metric MTS count per scan run — powers trend tracking and `compare` |
| `scan_summaries` | Per-run totals — powers `history` |
| `remediations` | Resolved findings with peak/current MTS and reduction % |
| `ignored` | Active ignore patterns |
| `trace_snapshots` | Per-service span counts per `trace-scan` run — powers `trace-compare` |

---

## Recommended cron

```cron
# Daily metric scan — builds history for compare and trend tracking
0 8 * * *  cd /path/to/o11y-usage-governance && \
           SPLUNK_ACCESS_TOKEN=... SPLUNK_REALM=us1 \
           python3 cardinality_governance.py scan --top 100

# Hourly trace snapshot — builds history for trace-compare
0 * * * *  cd /path/to/o11y-usage-governance && \
           SPLUNK_ACCESS_TOKEN=... SPLUNK_REALM=us1 \
           python3 cardinality_governance.py trace-scan --environment myenv
```

---

## Requirements

- Python 3.9+
- `requests` — Splunk API calls
- `boto3` — optional, required only for AI remediation (Claude via AWS Bedrock)

---

## Unified comparison: `usage-compare`

Runs metric MTS and trace span comparisons together in a single output. Designed for post-incident reviews where you want to see the full picture across both signals at once.

```bash
# Compare both signals between a stored date and now
python3 cardinality_governance.py usage-compare \
  --date1 2026-04-01 --date2 now --environment petclinicmbtest

# Two stored dates
python3 cardinality_governance.py usage-compare \
  --date1 2026-03-20 --date2 2026-04-01 --environment petclinicmbtest

# Adjust per-signal thresholds
python3 cardinality_governance.py usage-compare \
  --date1 2026-04-01 --date2 now \
  --metric-min-delta 50 --trace-min-delta 5
```

**Output structure:**

```
========================================================================================================================
  USAGE COMPARE  |  realm=us1  |  env=petclinicmbtest  |  2026-04-06 17:05 UTC
  Baseline: 2026-04-01   vs   Compared: now
========================================================================================================================

  [METRICS]  MTS cardinality comparison
  ...top metric increases, source breakdown...

  [TRACES]  APM span volume comparison
  ...top span increases by service, error rate changes...

========================================================================================================================
  SIGNAL SUMMARY
========================================================================================================================

  Both MTS and span volumes changed — likely a deployment or configuration change.
  Services implicated in BOTH signals: api-gateway, customers-service
  These are the highest-priority services to investigate.

  Metric change:  +4,210 MTS  (+98.3%)   ~$8.42/mo added
  Trace change:   +361 spans sampled  (+115.7%)
```

The signal summary cross-references the two signals and highlights services that appear in both — these are the most likely root cause of a billing spike or incident.

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--date1` / `--date2` | required | `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`, or `now` |
| `--environment` / `-e` | all | APM environment for trace section |
| `--metric-min-delta` | 100 | Minimum MTS change for metric section |
| `--trace-min-delta` | 10 | Minimum span delta for trace section |
| `--top` | 20 | Max rows per section |
| `--lookback` | 1.0 | Hours per window for live trace snapshots |
| `--show-dropped` | off | Show metrics/services that decreased |

---

## Anomaly detection: `anomaly-scan`

Flags metrics that are growing faster than their own historical baseline — regardless of whether they've crossed a static threshold. Catches slow-burn cardinality explosions early, before they become billing surprises.

```bash
# Default: flag metrics at 2x their 7-day average
python3 cardinality_governance.py anomaly-scan

# More sensitive: flag at 1.5x
python3 cardinality_governance.py anomaly-scan --ratio 1.5

# Longer baseline window
python3 cardinality_governance.py anomaly-scan --ratio 2.0 --days 14

# Require fewer history points (useful when history is sparse)
python3 cardinality_governance.py anomaly-scan --min-samples 2
```

**Output:**

```
Anomaly Scan  (realm=us1)
  Threshold: current MTS >= 2.0x 7-day average  |  min history points: 3

  Checked 50 metrics with 3+ history points.
  Found 5 anomalies  (2 already above static thresholds, 3 below thresholds but growing abnormally)

  BELOW-THRESHOLD ANOMALIES  —  growing fast but not yet CRITICAL/HIGH
  These would be MISSED by a static threshold scan.
  Metric                                             Current   7d Avg   Ratio  Samples  Severity
  http.client.request.duration_bucket                    480      120    4.0x        8  [MED]
  db.client.connections.wait_time_bucket                 240       60    4.0x        5  [LOW]
  container.cpu.usage                                    190       80    2.4x        6  [LOW]

  ABOVE-THRESHOLD ANOMALIES  —  flagged by static scan AND growing abnormally fast
  Metric                                             Current   7d Avg   Ratio  Samples  Severity
  k8s.pod.phase                                        1,500      400    3.8x        7  [HIGH]

  Top hidden anomaly: 'http.client.request.duration_bucket'
    Current MTS: 480  |  7-day avg: 120  |  Ratio: 4.0x  |  ~$0.96/mo
    Run: python3 cardinality_governance.py rollup --metric "http.client.request.duration_bucket"
```

**Why this matters:** static thresholds (`CRITICAL >= 10,000`) miss metrics that are growing quickly but haven't crossed the line yet. A metric at 800 MTS growing 4x per week will be at 50,000 MTS within two weeks. Anomaly scan catches it now while it's still cheap to fix.

**The anomaly flag also appears in regular `scan` output:**
```
Rank  Metric                               MTS   Trend        Severity
1     http.client.request.duration_bucket  480   GROWING      MEDIUM    [ANOMALY 4.0x]
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--ratio` | 2.0 | Flag if current MTS >= N × baseline average |
| `--days` | 7 | Baseline window length |
| `--min-samples` | 3 | Minimum scan history points required |
| `--top` | 20 | Max anomalies to show per section |

**Tip:** Override the default ratio globally:
```bash
export ANOMALY_RATIO=1.5        # more sensitive
export ANOMALY_MIN_SAMPLES=2    # less history required
```
