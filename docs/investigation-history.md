# Local investigation history (Task 9)

History uses Python's built-in `sqlite3`; no additional dependencies or remote database.
It is disabled by default. Existing analysis response bodies and scoring are unchanged.

## Enable or disable

Start the API with explicit configuration (bind to loopback):

```sh
export SUSNOT_HISTORY_ENABLED=true
# Optional absolute filesystem path; default: <project>/data/investigations.sqlite3
export SUSNOT_HISTORY_DB="$HOME/.susnot/investigations.sqlite3"
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

**Two opt-ins are required:** configuration above AND the header
`X-SUSNOT-Record-History: true` on each investigation request. For example:

```sh
curl http://127.0.0.1:8000/evaluate-url \
  -H 'Content-Type: application/json' \
  -H 'X-SUSNOT-Record-History: true' \
  -d '{"url":"https://example.com/verify"}'
```

The same header works on `/analyze-url` and `/analyze-text`. The existing Chrome
popup and Guardian requests do not send this header, so neither automatically
retains browsing history, even when server history is enabled. MCP and offline
benchmarks call the pure investigators and do not record history.

Unset `SUSNOT_HISTORY_ENABLED` or set it to `false` to disable recording and reading.
Only the value `true` (case-insensitive for the environment variable) enables it.
Disabled list requests return an empty page; detail requests return 404. Disabling
does not delete existing records. No database is created while disabled or during
an investigation without request consent. The database initializes lazily on the
first enabled history read or consenting write.

## Schema

Table: `investigations`. An index orders by UTC timestamp and ID descending.

| Column | SQLite type | Meaning |
| --- | --- | --- |
| investigation_id | TEXT PRIMARY KEY | Generated UUID |
| timestamp_utc | TEXT NOT NULL | ISO 8601 UTC recording time, with `+00:00` offset |
| investigation_type | TEXT NOT NULL | `URL` or `text` |
| redacted_url | TEXT nullable | Only `http://[redacted]` or `https://[redacted]`; null for text |
| sus_score | INTEGER nullable | Unchanged URL heuristic score |
| risk_level | TEXT nullable | URL risk level |
| indicators | TEXT NOT NULL | JSON array of fixed URL indicator descriptions or text presence marker |
| recommended_action | TEXT nullable | Deterministic policy action for `/evaluate-url` only |
| policy_version | TEXT nullable | Policy version for `/evaluate-url` only |
| analysis_status | TEXT NOT NULL | `completed` or `failed` |

Successful consenting URL and text requests are recorded. Text investigation
HTTP failures record only type, ID, time, failed status, and empty indicators.
Input validation failures are not recorded. Text has no numeric score, risk,
policy version, or retained recommendation. Recording failures do not change
analysis responses; history reads return a generic 503 when storage is unavailable.
This minimal version has no migrations, retention scheduler, or write-delivery guarantee.

## Privacy boundaries

- Never persists submitted text, model findings/prose, explanations, uncertainty,
  or model recommendations: these can echo private input. Text `indicators` is
  only `["model_reported_indicators"]` when the model returned any findings, or `[]`.
  It is not a retained finding or independently validated category.
- URL redaction removes the entire authority (including host, credentials and port),
  path, query and fragment. Hostnames and paths can themselves contain identifiers.
  Only the scheme remains. URL indicators are fixed application-owned strings.
- Uses parameterized SQL for record values, lookup IDs, and pagination. HTTP detail
  IDs must be UUIDs. No submitted content, credentials, API keys, or database exception
  details are logged by the history code.
- API keys/credentials should not be supplied in request URLs or shell commands.
  Analysis endpoints still return their existing bodies (including the submitted
  URL or model prose); history redaction does not change those responses.
- Records are plaintext local metadata, not encrypted or authenticated. Restrict
  filesystem permissions and keep the API on loopback. Do not expose history endpoints
  to untrusted users. Existing access logs and external proxies are outside this store.
- Database files are ignored by Git. OS backups, synced directories, and filesystem
  permissions remain the operator's responsibility; choose a non-synced local path.

These protections are intentionally limited, not comprehensive or independently
audited. Timestamps, indicator presence and scores remain potentially sensitive.
Because source evidence is omitted, history supports reviewing outcomes and policy
versions, not reconstructing or exactly replaying the original investigation.

## Inspect and paginate

```sh
curl 'http://127.0.0.1:8000/investigations?limit=20&offset=0'
curl 'http://127.0.0.1:8000/investigations/UUID-FROM-LIST'
```

The list returns `{items, total, limit, offset}`, newest first. `limit` defaults
to 20 and must be 1–100; `offset` defaults to 0 and must be nonnegative. Invalid
parameters/IDs return 422; missing records return 404. Offset pages can shift
when new records arrive. Only stored minimized metadata is returned, never fresh
model output or Chrome history.

With an installed SQLite CLI, inspect locally:

```sh
sqlite3 "$SUSNOT_HISTORY_DB" 'SELECT * FROM investigations ORDER BY timestamp_utc DESC LIMIT 20;'
```

`backend.history.HistoryStore` also offers `initialize`, `create`, `get`, and `list`
for local Python consumers. It is a low-level trusted metadata store: callers must
minimize data before calling `create`; it is not a generic secret scrubber.

## Reset

Stop the API and any local readers, then delete the configured database (default
`data/investigations.sqlite3`) and any matching `-journal`, `-wal`, or `-shm` sidecars.
For the default path:

```sh
rm -f data/investigations.sqlite3 data/investigations.sqlite3-journal \
  data/investigations.sqlite3-wal data/investigations.sqlite3-shm
```

The next enabled history operation recreates an empty schema. File deletion is
not guaranteed secure erasure, and backups must be managed separately.

## Future Streamlit dashboard

A future local Streamlit dashboard can consume the paginated API or use
`HistoryStore.list/get` for timelines, score distributions and policy-version
comparisons. It should display only these minimized records, respect enablement,
and never infer missing source evidence or read Chrome browsing history. No
dashboard, background collection, or new dependency is added by this task.

## Tests

Tests use temporary databases and mocked Ollama responses. Run:

```sh
.venv/bin/python -m pytest -q
node --test tests/*.test.cjs
```
