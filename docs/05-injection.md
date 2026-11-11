# 05 · Injection

Checklist section: **§5 Injection** · Module: `m05-injection` · Port: **8085**
PoC: [`attacks/05-injection.sh`](../attacks/05-injection.sh) · Run: `scripts/run-module.sh m05-injection`

Data comes from `data.sql`: four subscriptions and an `integration_credentials` table. That second
table is the point of the SQLi demo — *if the application user can read the credentials table, SQL
injection is a credential leak, not just a data leak* (checklist §3 and §5 meet here).

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | SQL injection in a JDBC query | CWE-89 | `GET /vuln5/subscriptions?email=` | `GET /safe5/subscriptions` (bound + shape-checked) |
| 2 | `LIKE` built by concatenation, wildcards unescaped | CWE-89 | `GET /vuln5/search?q=%` | `GET /safe5/search` (`?` + `ESCAPE '\'`) |
| 3 | `ORDER BY` from the request | CWE-89 | `GET /vuln5/list?sort=` | `GET /safe5/list` (allow-list) |
| 4 | JPQL assembled with concatenation | CWE-89 | `GET /vuln5/jpa?plan=` | `GET /safe5/jpa` (named parameters) |
| 5 | Native query assembled with concatenation | CWE-89 | `GET /vuln5/native?tenantId=` | — see "correction" below |
| 6 | SpEL injection (input reaches the expression parser) | CWE-917 | `GET /vuln5/report?expr=` | `GET /safe5/report?template=` (registry) |
| 7 | OS command injection via shell-composed string | CWE-78 | `POST /vuln5/tools/ping?host=` (`VULNRANGE_ALLOW_EXEC=true`) | `POST /safe5/tools/ping` (validated argv) |
| 8 | CRLF log forging | CWE-117 | `POST /vuln5/audit/message` | `POST /safe5/audit/message` |
| 9 | DB error text returned to the caller | CWE-209 | inside `/vuln5/list` | removed (see `m09`) |

## Reproduce

```bash
attacks/05-injection.sh

# boolean bypass
curl -s "http://127.0.0.1:8085/vuln5/subscriptions?email=x'%20OR%20'1'='1"
# UNION into the credentials table
curl -s "http://127.0.0.1:8085/vuln5/subscriptions?email=x'%20UNION%20SELECT%20service_name,env,api_key,1%20FROM%20integration_credentials%20--"
# order-by blind extraction
curl -s "http://127.0.0.1:8085/vuln5/list?sort=CASE%20WHEN%20(1=1)%20THEN%20id%20ELSE%20plan%20END"
```

For the command-injection demo, start the module with the sink enabled — deliberately opt-in,
because a reachable version of that method is arbitrary command execution on the host:

```bash
VULNRANGE_ALLOW_EXEC=true scripts/run-module.sh m05-injection
curl -s -X POST 'http://127.0.0.1:8085/vuln5/tools/ping?host=127.0.0.1;id'
```

## Correction worth recording

The `/vuln5/native` demonstration originally read `invoker.invoke` output through a `Map<String,Object>`
result type, which is not what a native query returns (it returns `Object[]` rows). The endpoint now
maps the row array explicitly. This is exactly the kind of mistake a compiler catches in one run and a
review catches never — which is why `scripts/verify_range.sh` exists and why the module must be built
before it is demoed.

## Fix, in the order that matters

1. **Bind every value.** `JdbcTemplate` with `?`, Spring Data derived queries, JPQL named parameters.
2. **Identifiers cannot be bound** — resolve them from an allow-list (`SAFE_SORTABLE`).
3. **`LIKE` needs escaping** plus an explicit `ESCAPE` clause; otherwise `%` is a free wildcard.
4. **No user input reaches an expression parser.** If expressions are a feature, keep them in a
   registry owned by developers and evaluate them in a read-only `SimpleEvaluationContext`.
5. **No shell.** `ProcessBuilder` with separate argv elements, validated input, timeouts, and no
   `sh -c`.
6. **Sanitise before logging:** strip CR/LF/NUL, bound length (`CorrelationIdFilter.sanitiseForLog`).
7. **Least privilege in the database:** a runtime user that cannot read the credentials table turns
   the UNION above into an error instead of a breach.

## Detection

* FindSecBugs `SQL_INJECTION_JDBC`, `CRLF_INJECTION_LOGS`, `SPEL_INJECTION`; Semgrep rules
  `spring-sql-string-concatenation`, `spring-sql-string-concatenation` for JPQL.
* Grep the diff for `" + ` inside strings that reach `query(`, `createQuery(`, `ORDER BY`.
* Log-injection: alert on log lines containing `\n` inside a message field (structured logging makes
  this a query, not a prayer).
