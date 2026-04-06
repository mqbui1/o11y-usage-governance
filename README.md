# Metric Cardinality Governance

Scans a Splunk Observability Cloud org for MTS (Metric Time Series) cardinality explosions, attributes them to teams and services, identifies the instrumentation source, tracks trends over time, and uses Claude (AWS Bedrock) to generate specific remediation recommendations.

## Why it matters

High-cardinality metrics are the #1 cause of surprise overage bills in Splunk Observability Cloud. A single metric with an unbounded dimension (UUID, IP address, user ID, request ID) can generate millions of MTS without the team responsible ever knowing. This tool provides continuous visibility and actionable fixes.

**Common culprits:**
- Pod IP addresses as metric dimensions in Kubernetes
- UUIDs or trace IDs embedded in metric labels
- High-cardinality HTTP routes or user identifiers
- Histogram bucket metrics (`_bucket`) with unbounded label combinations

## How it works

1. **Paginated catalog scan** — fetches the complete metric catalog (no cap), iterates every metric
2. **MTS analysis** — counts MTS per metric, samples dimension values to detect anti-patterns
3. **Instrumentation source detection** — identifies whether the metric comes from OTel Collector, OTel SDK, JVM, Kubernetes, AWS, MySQL, etc.
4. **Team attribution** — maps metrics to services/teams via `service.name`, `team`, and `owner` dimensions
5. **Trend tracking** — compares current MTS count to previous scan (stored in SQLite), flags GROWING/FALLING/NEW/STABLE
6. **Org limit awareness** — fetches org MTS limit and shows each finding's % contribution
7. **Per-service scorecard** — ranks services/teams by total MTS contributed across all findings, showing ownership and % of total
8. **Duplicate metric grouping** — identifies metrics sharing the same high-cardinality dimension and groups metric families (e.g. `_bucket/_count/_sum/_min/_max` variants) — one fix resolves the whole group
9. **Fix suggestion generator** — for each duplicate group, auto-generates ready-to-paste OTel Collector `transform` processor YAML with the exact `delete_key()` statement and metric allow-list scoped to only the affected metrics; includes a collapsible SHA256-hash alternative
10. **Remediation tracking** — automatically detects when a metric's MTS drops >50% vs its historical peak and marks it resolved; supports manual `resolve` command; resolved findings appear at the top of the next report confirming the fix worked
11. **Cost estimation** — maps MTS count to estimated monthly cost (default `$0.002/MTS/mo`, configurable via `MTS_COST_PER_MONTH` env var); shown in report header, Top Offenders table, and per-service scorecard
12. **Savings summary** — report header and Resolved Findings section show cumulative MTS and cost saved across all remediated metrics
13. **Dimension drill-down** — `drilldown --dimension <name>` scans every metric in the org for that dimension, ranks by unique value count, shows combined MTS + cost, and generates a single fix YAML covering the full blast radius
14. **False positive suppression** — `ignore <pattern>` excludes a metric name or glob (e.g. `sf.org.*`, `otelcol_*`) from all future scans and reports; `unignore` removes it; ignored count shown in report summary
15. **Scan history** — `history` prints a table of past scans (total metrics, MTS, cost, severity counts) with a trend arrow showing whether the org is getting better or worse over time
16. **HTML report** — `report --format html` generates a self-contained HTML file with sortable tables, tabbed layout, stat cards, alert banners, collapsible findings, and fix YAML — no external dependencies, shareable as a single file
17. **AI remediation** — for CRITICAL and HIGH findings, calls Claude to generate specific OTel Collector processor configs, SignalFlow rollups, and estimated MTS reduction

## Modes

| Command | Description |
|---------|-------------|
| `scan` | Quick ranked table of top offenders with trend, source, and severity |
| `report` | Full Markdown or HTML report saved to `reports/` with AI remediation for CRITICAL/HIGH |
| `watch` | Continuous polling — emits Splunk custom events on new explosions and growth spikes |
| `rollup` | Deep-dive on a single metric — dimension analysis + SignalFlow rollup + OTel processor config |
| `resolve` | Manually mark a metric as remediated after applying a fix |
| `drilldown` | Show every metric carrying a given dimension — full blast radius + combined fix YAML |
| `ignore` | Exclude a metric name or glob pattern from future scans and reports |
| `unignore` | Remove a pattern from the ignore list |
| `ignored` | List all currently ignored patterns |
| `history` | Show scan history — total MTS, cost, and severity trend over time |

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export SPLUNK_ACCESS_TOKEN=<your-api-token>
export SPLUNK_REALM=us1                          # us0, us1, us2, eu0, ap0, etc.
export SPLUNK_INGEST_TOKEN=<your-ingest-token>   # optional — needed for watch mode events
export AWS_DEFAULT_REGION=us-west-2              # needed for Claude AI remediation (Bedrock)
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
export AWS_SESSION_TOKEN=<token>                 # if using temporary credentials
```

## Usage

```bash
# Quick scan — top 20 metrics ranked by MTS count
python3 cardinality_governance.py scan

# Show all metrics including low severity
python3 cardinality_governance.py scan --verbose

# Show top 50 metrics
python3 cardinality_governance.py scan --top 50

# Full Markdown report with AI remediation (saved to reports/)
python3 cardinality_governance.py report

# Report without AI — faster, no Bedrock credentials needed
python3 cardinality_governance.py report --no-ai

# HTML report — opens in browser automatically on macOS
python3 cardinality_governance.py report --format html

# Generate both Markdown and HTML
python3 cardinality_governance.py report --format both --no-ai

# Report for top 100 metrics
python3 cardinality_governance.py report --top 100

# Watch mode — poll every 5 minutes, emit Splunk events on explosions
python3 cardinality_governance.py watch --interval 300

# Watch mode with custom threshold
python3 cardinality_governance.py watch --threshold 5000

# Deep-dive rollup suggestion for a specific metric
python3 cardinality_governance.py rollup --metric http.client.request.duration_bucket

# Manually mark a metric as resolved after applying a fix
python3 cardinality_governance.py resolve --metric http.client.request.duration_bucket
python3 cardinality_governance.py resolve --metric http.client.request.duration_bucket --note "applied delete_key(server.address) in collector v1.2"

# Dimension drill-down — full blast radius for a specific dimension
python3 cardinality_governance.py drilldown --dimension server.address
python3 cardinality_governance.py drilldown --dimension container.id --top 20

# Ignore metrics you can't control (Splunk internals, collector telemetry)
python3 cardinality_governance.py ignore "sf.org.*" --reason "Splunk internal — cannot remediate"
python3 cardinality_governance.py ignore "otelcol_*" --reason "Collector internal telemetry"
python3 cardinality_governance.py ignored          # list all ignored patterns
python3 cardinality_governance.py unignore "sf.org.*"

# Scan history — trend over time
python3 cardinality_governance.py history
python3 cardinality_governance.py history --limit 10
```

## Scan output columns

```
Rank  Metric                              MTS   Trend        Severity    Source               Worst Dimension
1     http.client.request.duration_bucket  1,215 ➡️STABLE    🟠HIGH      HTTP Instrumentation  server.address (21 values)
2     http.server.request.duration_bucket    810 📈GROWING+30% 🟡MEDIUM  HTTP Instrumentation  http.route (24 values)
```

| Column | Description |
|--------|-------------|
| MTS | Total metric time series count for this metric |
| Trend | Change since last scan: 📈 GROWING / 📉 FALLING / ➡️ STABLE / 🆕 NEW |
| Severity | Based on MTS count thresholds |
| Source | Inferred instrumentation origin |
| Worst Dimension | Highest-cardinality dimension and its unique value count |

## Severity thresholds

| Severity | MTS Count | Meaning |
|----------|-----------|---------|
| 🔴 CRITICAL | ≥ 10,000 | Immediate action required — significant billing impact |
| 🟠 HIGH | ≥ 1,000 | Investigate and plan remediation |
| 🟡 MEDIUM | ≥ 500 | Monitor and address in next sprint |

## Instrumentation source detection

The tool automatically identifies where a metric is coming from based on its name prefix and dimensions:

| Source | Metric prefix examples |
|--------|----------------------|
| OTel Collector | `otelcol_*` |
| OTel SDK | `otel.sdk.*` |
| JVM | `jvm.*`, `process.runtime.jvm.*` |
| Kubernetes | `k8s.*` |
| Host / OS | `system.*`, `process.*` |
| HTTP Instrumentation | `http.*` |
| Database | `db.*`, `mysql.*`, `postgresql.*`, `redis.*` |
| Messaging | `messaging.*`, `kafka.*` |
| Cloud | `aws.*`, `azure.*`, `gcp.*` |
| Splunk Agent | `sf.*`, `splunk.*` |

## Anti-pattern detection

Automatically flags dimensions whose values match high-cardinality patterns:

| Pattern | Example |
|---------|---------|
| UUID | `550e8400-e29b-41d4-a716-446655440000` |
| IP address | `10.42.2.32` |
| Timestamp / epoch | `1712345678901` |
| MD5 hash | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 hash | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| Very long string | Any value > 100 characters |

## Trend tracking

After each scan, results are saved to `cardinality_state.db` (SQLite). On subsequent runs, each metric is compared to its previous value:

- **🆕 NEW** — metric not seen in previous scan
- **📈 GROWING** — MTS count increased >20% since last scan
- **📉 FALLING** — MTS count decreased >20% (remediation may be working)
- **➡️ STABLE** — within ±20% of last scan

The state DB persists across runs — run `scan` or `report` regularly (e.g. daily via cron) to build trend history.

## Watch mode events

When running in `watch` mode, the tool emits custom events to Splunk Observability Cloud that can be used in dashboards and detectors:

| Event type | Triggered when |
|------------|---------------|
| `cardinality.explosion.detected` | A metric crosses the MTS threshold for the first time |
| `cardinality.explosion.growing` | An existing high-cardinality metric grew >50% since last poll |

## Report output

Reports are saved to `reports/cardinality_report_<timestamp>.md` and include:

- **Header** — org realm, total MTS across findings, org limit and % used
- **Summary table** — count by severity
- **Trend alerts** — new metrics and growing metrics since last scan
- **Top offenders table** — ranked with MTS count, % of org limit, trend, severity, source, worst dimension
- **Per-service cardinality scorecard** — ranks services by total MTS contributed, affected metric count, and % of findings total
- **Duplicate / similar metric groups** — two views:
  - *By shared worst dimension*: all metrics with the same offending dimension grouped together with combined MTS and "one fix resolves all N" callout
  - *By metric family*: `_bucket/_count/_sum/_min/_max/_total` variants grouped under their common root name, confirming they share the same problem dimension
- **Fix suggestion YAML** — inline per group: ready-to-paste OTel Collector processor config to drop or hash the offending dimension (see below)
- **Resolved findings** — metrics that previously exceeded thresholds and have since dropped >50% MTS; shown at the top of the report confirming the fix worked
- **Detailed findings** — per-metric breakdown with dimension cardinality table, estimated cost, and sample values
- **AI remediation** (CRITICAL/HIGH only) — root cause, OTel Collector processor config, SignalFlow rollup, estimated MTS reduction

## Per-service cardinality scorecard

Shows which services own the most cardinality across all findings. Useful for directing remediation effort to the highest-impact team.

```
| Rank | Service            | Total MTS | Affected Metrics | % of Findings Total |
|------|--------------------|-----------|-----------------|---------------------|
| 1    | customers-service  | 3,442     | 25              | 58.9%               |
| 2    | api-gateway        | 3,298     | 22              | 56.5%               |
| 3    | unknown            | 2,139     | 20              | 36.6%               |
```

## Duplicate / similar metric groups

Identifies metrics that share the same root cardinality problem, so a single OTel Collector processor fix resolves multiple metrics at once.

**Grouped by shared worst dimension:**
```
#### Dimension: `server.address` (21 unique values)
Anti-pattern detected: IP address
Combined MTS: 1,539 | Metrics in group: 5 | One fix resolves all 5

| Metric                                  | MTS   | Severity    |
|-----------------------------------------|-------|-------------|
| http.client.request.duration_bucket     | 1,215 | CRITICAL    |
| http.client.request.duration_min        | 81    | CRITICAL    |
| http.client.request.duration_count      | 81    | CRITICAL    |
| http.client.request.duration_sum        | 81    | CRITICAL    |
| http.client.request.duration_max        | 81    | CRITICAL    |
```

**Grouped by metric family (same root name):**
```
#### Family: `http.client.request.duration_*`
Combined MTS: 1,539 | Variants: 5 | Shared problem dimension: `server.address`
```

## HTML report

```bash
python3 cardinality_governance.py report --format html --no-ai
```

Generates a self-contained `.html` file in `reports/` — no external dependencies, shareable as a single file attachment. Opens automatically in the browser on macOS.

**Six tabs:**
- **Top Offenders** — full ranked table with MTS, cost, severity, trend, source, worst dimension
- **Service Scorecard** — per-service MTS and cost with inline progress bars
- **Duplicate Groups** — metrics sharing the same root cause, with collapsible fix YAML per group
- **Resolved** — confirmed remediations with MTS and cost savings
- **Detailed Findings** — collapsible per-metric detail with dimension tables and AI remediation
- **Ignored** — active ignore patterns

**All tables are sortable** — click any column header to sort ascending/descending.

**Summary cards** at the top show total MTS, estimated cost, severity counts, and cumulative savings at a glance.

## False positive suppression

Some metrics will always appear as findings even though nothing can be done about them — `sf.org.*` Splunk internal metrics, `otelcol_*` collector self-telemetry, etc. The ignore list excludes these permanently so the report stays focused on actionable findings.

```bash
# Ignore Splunk internal metrics
python3 cardinality_governance.py ignore "sf.org.*" --reason "Splunk internal — cannot remediate"

# Ignore OTel Collector internal metrics
python3 cardinality_governance.py ignore "otelcol_*" --reason "Collector internal telemetry"

# List active patterns
python3 cardinality_governance.py ignored

# Remove a pattern
python3 cardinality_governance.py unignore "sf.org.*"
```

Patterns support `fnmatch` glob syntax (`*` matches any characters, `?` matches one character). Ignored patterns are stored in `cardinality_state.db` and persist across runs. The report Summary table shows the ignored count.

## Scan history

Every `scan` or `report` run saves a summary row to SQLite. The `history` command shows the trend over time:

```bash
python3 cardinality_governance.py history
```

```
Scan history (realm=us1, last 7 scans)

Date                    Metrics  Total MTS  Est Cost/Mo     🔴     🟠     🟡  Ignored
2026-04-01 08:00          1,038     12,450     ~$24.90     8      5      3       12
2026-04-02 08:00          1,041     13,200     ~$26.40    10      5      3       12
2026-04-03 08:00          1,041      9,800     ~$19.60     6      4      3       12
...

Trend over 7 scans: 📉 DOWN 21.3%  (-2,650 MTS  /  ~-$5.30/mo)
```

Shows whether the org's cardinality is trending better or worse, and quantifies the impact of remediations over time.

## Dimension drill-down

Before applying a fix, use `drilldown` to see the full blast radius — every metric carrying the dimension, not just the ones that crossed severity thresholds.

```bash
python3 cardinality_governance.py drilldown --dimension server.address
```

Output:
```
Dimension drill-down: `server.address` (realm=us1)

  Found 16 metric(s) carrying `server.address`
  Combined MTS: 861  |  Est. cost: ~$1.72/mo
  Max unique values seen: 21
  Anti-pattern detected: IP address

Rank  Metric                               MTS   Unique Values  Pattern     Source                Services
1     http.client.request.duration_min      81              21  IP address  HTTP Instrumentation  admin-server, api-gateway
2     http.client.request.duration_bucket  500              11  IP address  HTTP Instrumentation  admin-server, api-gateway
3     coredns_dns_requests_total             4               1  IP address  Kubernetes (app)      coredns
...

FIX: Drop `server.address` from all 16 affected metrics
======================================================================
processors:
  transform/drop_server_address:
    ...
```

The drill-down often reveals more affected metrics than the report's duplicate grouping — low-MTS metrics that didn't cross the severity threshold but share the same problematic dimension. The generated fix YAML covers all of them in one config block.

## Cost estimation and savings

MTS count is converted to an estimated monthly cost throughout the report. The default rate is **$0.002 per MTS per month** — a conservative mid-tier estimate for Splunk Observability Cloud custom metrics.

Override the rate to match your org's actual contract:
```bash
export MTS_COST_PER_MONTH=0.005   # $0.005/MTS/mo (higher tier)
python3 cardinality_governance.py report
```

Cost appears in three places:
- **Report header** — total estimated cost across all findings
- **Top Offenders table** — `Est. Cost/Mo` column per metric
- **Per-Service Scorecard** — `Est. Cost/Mo` column per service

Example header output:
```
Total MTS across findings: 2,500,000
Estimated monthly cost (findings only): ~$5,000.00/mo (at $0.002/MTS/mo)
Cumulative savings (resolved findings): 800,000 MTS / ~$1,600.00/mo saved across 3 resolved metric(s) 🎉
```

As fixes are applied and metrics are marked resolved, the savings line grows — giving a running total of cost reduction attributed to the governance program.

## Remediation tracking

Closes the loop between finding a problem and confirming the fix worked.

**Auto-detection:** every `scan` or `report` run checks whether each metric's current MTS has dropped >50% vs its historical peak. If so, it's automatically marked resolved and a `[RESOLVED]` notice is printed.

**Manual resolve:** after deploying the generated OTel Collector processor config, mark the fix explicitly:
```bash
python3 cardinality_governance.py resolve \
  --metric http.client.request.duration_bucket \
  --note "applied delete_key(server.address) in collector config v1.2"
```

**Resolved findings** appear at the top of the next report:
```
## Resolved Findings
> These metrics previously exceeded severity thresholds and have since dropped >50% — fix confirmed working.

| Metric                              | Peak MTS | Current MTS | Reduction | Resolved At | How  |
|-------------------------------------|----------|-------------|-----------|-------------|------|
| http.client.request.duration_bucket | 1,215    | 400         | -67.1%    | 2026-04-06  | auto |
```

Resolution state is stored in `cardinality_state.db`. If a resolved metric later re-explodes past the threshold, it will reappear in Top Offenders on the next scan.

## Fix suggestion generator

Every duplicate group in the report includes two ready-to-paste OTel Collector processor configs.

**Option 1 — Drop the dimension entirely** (shown inline):
```yaml
# OTel Collector processor — drop `server.address` from 5 metric(s)
# Dimension has 21 unique values (IP address)
# Effect: eliminates the cardinality explosion; metric is still reported per remaining dimensions.
processors:
  transform/drop_server_address:
    metric_statements:
      - context: datapoint
        statements:
          - delete_key(attributes, "server.address")  # anti-pattern: IP address
        # Apply only to these metrics (remove 'include' block to apply to all):
        include:
          match_type: strict
          metric_names:
            - 'http.client.request.duration_bucket'
            - 'http.client.request.duration_count'
            - 'http.client.request.duration_max'
            - 'http.client.request.duration_min'
            - 'http.client.request.duration_sum'

service:
  pipelines:
    metrics:
      processors: [transform/drop_server_address, ...]
```

**Option 2 — Hash instead of drop** (collapsible, use when cross-restart correlation is needed):
```yaml
processors:
  transform/hash_server_address:
    metric_statements:
      - context: datapoint
        statements:
          - set(attributes["server.address"], SHA256(attributes["server.address"]))
        include:
          match_type: strict
          metric_names:
            - 'http.client.request.duration_bucket'
            ...
```

Each processor is named `transform/drop_<dim>` or `transform/hash_<dim>` and scoped to only the affected metrics via `include.metric_names`, so it won't accidentally affect unrelated metrics that happen to share the same dimension name.

## MTS spike comparison

Compare MTS counts between any two points in time to identify what caused a cardinality spike and which service/token is responsible.

```bash
# Compare stored April 1 snapshot vs live data now
python3 cardinality_governance.py compare --date1 2026-04-01 --date2 now

# Compare two stored scan dates
python3 cardinality_governance.py compare --date1 2026-03-20 --date2 2026-04-01

# Lower threshold to catch smaller changes; also show drops
python3 cardinality_governance.py compare --date1 2026-04-01 --date2 now \
  --min-delta 10 --show-dropped

# Focus on top 10 biggest movers
python3 cardinality_governance.py compare --date1 2026-04-01 --date2 now --top 10 --no-new
```

**Output sections:**

| Section | What it shows |
|---|---|
| Summary header | Total MTS baseline → compared, net delta, monthly cost impact |
| Top MTS Increases | Metrics that grew by ≥ `--min-delta` MTS, sorted by delta |
| Source breakdown | Aggregates increases by instrumentation source (OTel SDK, OTel Collector, Kubernetes, etc.) |
| Token breakdown | Aggregates increases by ingest token — pinpoints which pipeline/team drove the spike |
| New Metrics | Metrics that appear in the compared snapshot but not the baseline |
| Biggest Drops | (with `--show-dropped`) Metrics that shrank most |

**How dates work:**
- `now` — fetches a live snapshot from the API (takes ~2-5 minutes for large orgs)
- `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM` — looks up the stored scan closest to that date/time
- If no stored scan is available near the given date, falls back to a live API fetch

**Tip:** Run `scan` regularly (e.g. daily via cron) to build up history, then use `compare` to instantly diff any two stored dates without re-fetching data.

**Example output:**
```
MTS Spike Comparison  (realm=us1)  generated 2026-04-06 16:29 UTC

  Baseline  (2026-04-05T04:29):       4,283 MTS   ~$8.57/mo
  Compared  (2026-04-06T16:29):       8,493 MTS   ~$16.99/mo
  Net change:               +    4,210 MTS  (+98.3%)   ~$8.42/mo added

========================================================================================================================
  TOP MTS INCREASES  (>=100 MTS delta)  --  12 metric(s)
========================================================================================================================
Rank  Metric                                             Baseline    Current      Delta   Change  Source                    Services / Token
1     http.server.request.duration_bucket                     120         480       +360   +200.0%  OTel SDK (app)            api-gateway, customers-service [petclinic-INGEST]
2     http.client.request.duration_bucket                      80         320       +240   +200.0%  OTel SDK (app)            visits-service [petclinic-INGEST]
...

  Source breakdown for increased metrics:
  Source                         Metrics    MTS Added     Cost Added
  OTel SDK (app)                      8        2,840      ~$5.68/mo
  OTel Collector                      3          890      ~$1.78/mo

  Token breakdown for increased metrics:
  Token                              Metrics    MTS Added
  petclinic-INGEST                        8        2,840
  petclinicmcptest-INGEST                 3          890

========================================================================================================================
  NEW METRICS  (first seen in compared snapshot)  --  5 metric(s)
========================================================================================================================
Rank  Metric                                                  MTS  Source                    Services / Token
1     otelcol_k8s_pod_association                              65  OTel Collector            otel-agent
```
