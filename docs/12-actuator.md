# 12 · Management endpoints, API documentation and debug surfaces

Checklist section: **§12 Actuator, API docs, debug endpoints** · Module: `m12-actuator` · Port: **8092** (management **8192** in the safe profile)
PoC: [`attacks/12-actuator.sh`](../attacks/12-actuator.sh) · Run: `scripts/run-module.sh m12-actuator`

There is no `/safe12` package in this module, on purpose: the hardening is configuration. The same jar
starts twice — default profile (everything exposed on the public port) and `--spring.profiles.active=safe`
(`application-safe.yml` plus `ActuatorChainConfig.hardenedChain`, management on a separate loopback port).
The difference is a diff, not a narrative.

## What this module demonstrates

| # | Vulnerability | CWE | Insecure | Hardened |
|---|---------------|-----|----------|----------|
| 1 | Every web endpoint exposed | CWE-200 | `management.endpoints.web.exposure.include: '*'` → `/actuator` inventory | `include: 'health,info'` in `application-safe.yml`; `/actuator/env` is 404 |
| 2 | Health details for anonymous callers | CWE-200 | `GET /actuator/health` (`show-details: always`, `show-components: always`) | `show-details: never`, `show-components: never`, `down` → 503 |
| 3 | Property sources with values | CWE-200, CWE-312 | `GET /actuator/env` (`show-values: always`) | `management.endpoint.env.enabled: false`; `/actuator/env` → 401 |
| 4 | Configuration properties with values | CWE-200, CWE-312 | `GET /actuator/configprops` (`show-values: always`) | `management.endpoint.configprops.enabled: false` |
| 5 | Memory dump in one request | CWE-200 | `GET /actuator/heapdump` | `management.endpoint.heapdump.enabled: false`; `/actuator/heapdump` → 401 |
| 6 | Runtime log levels remotely settable | CWE-200, CWE-770 | `POST /actuator/loggers/ROOT` (`{"configuredLevel":"DEBUG"}`) | `management.endpoint.loggers.enabled: false` |
| 7 | Thread dump on demand | CWE-200 | `GET /actuator/threaddump` | `management.endpoint.threaddump.enabled: false` |
| 8 | Remote shutdown on the public port | CWE-306, CWE-749 | `POST /actuator/shutdown` (`management.endpoint.shutdown.enabled: true`) | `management.endpoint.shutdown.enabled: false` |
| 9 | Complete route map, including debug routes, served unauthenticated | CWE-200 | `GET /api-docs/openapi.json` (lists `/vuln12/debug/reset-cache`) | no static description in the safe profile |
| 10 | SQL console shipped "temporarily" | CWE-1188, CWE-306 | `GET /h2-console` (`spring.h2.console.enabled: true`) | `spring.h2.console.enabled: false` |
| 11 | Build metadata maps the estate | CWE-200 | `GET /actuator/info` (`info.build.scm`, branch) | `info` reduced to `app.name`; `management.info.env.enabled: false` |
| 12 | All of the above anonymously | CWE-306 | `exposedChain`: `permitAll()`, `csrf().disable()` | `hardenedChain`: `/actuator/health` and `/actuator/info` public, `/actuator/**` needs `ROLE_ACTUATOR`, `anyRequest().denyAll()`, HTTP Basic, CSRF on |

## Reproduce

```bash
attacks/12-actuator.sh

# endpoint inventory an anonymous caller sees in the default profile
curl -s http://127.0.0.1:8092/actuator

# component data: database, disk, internal names
curl -s http://127.0.0.1:8092/actuator/health

# property sources with values
curl -s http://127.0.0.1:8092/actuator/env

# configuration properties with values
curl -s http://127.0.0.1:8092/actuator/configprops

# one request, everything in memory
curl -s -o /tmp/m12-heapdump.hprof -w '%{size_download} bytes\n' http://127.0.0.1:8092/actuator/heapdump

# log level turned up remotely, then read back
curl -s -X POST -H 'Content-Type: application/json' -d '{"configuredLevel":"DEBUG"}' \
     http://127.0.0.1:8092/actuator/loggers/ROOT
curl -s http://127.0.0.1:8092/actuator/loggers/ROOT

# the published route map, debug route included
curl -s http://127.0.0.1:8092/api-docs/openapi.json

# and the debug route it advertises really is there, anonymous and state-changing
curl -s -X POST http://127.0.0.1:8092/vuln12/debug/reset-cache

# ordinary business endpoint, so the module has something legitimate to serve
curl -s http://127.0.0.1:8092/api/orders
```

The thread dump is plain JSON over the same port; the frames already name internal classes, libraries
and connection pools:

```bash
curl -s http://127.0.0.1:8092/actuator/threaddump | head -20
```

The hardened shape is the same jar, restarted:

```bash
scripts/stop-all.sh
java -jar m12-actuator/target/m12-actuator-1.0.0.jar --spring.profiles.active=safe

curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8092/actuator/health   # 200, no component data
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8092/actuator/env      # 404, not exposed
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8192/actuator/health   # 200 on the management port
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8192/actuator/heapdump # 401 for anonymous callers
```

`/actuator/**` on the management port answers to the `operator` user defined in
`ActuatorChainConfig.users`. The password there is a literal in code and is itself a finding: in a real
service the operator account comes from the deployment's identity provider, not from a builder call.

Two caveats when reading the status codes above. In the default profile `POST /actuator/shutdown` is
enabled and unmasked but already POST-only; `curl -s -X POST http://127.0.0.1:8092/actuator/shutdown`
stops the module, so run it last. And `/actuator/threaddump` on a large heap can exceed the 8 s timeout
in `attacks/lib.sh`; use `curl` directly if the request is slow rather than concluding the endpoint is
closed.

## Fix, in the order that matters

1. **Expose only what a probe needs.** `management.endpoints.web.exposure.include: 'health,info'` in
   `application-safe.yml`. Everything else is disabled, not merely unlisted — `env`, `configprops`,
   `heapdump`, `threaddump`, `loggers` all have `enabled: false`.
2. **No values in responses.** `show-values` and `show-details` are `never` unless the caller is
   authenticated; a health endpoint that names the database product and the disk path is reconnaissance.
3. **A separate, non-routable management port.** `management.server.port: 8192`,
   `management.server.address: 127.0.0.1`. The ingress serves `:8092` and cannot reach `:8192`.
4. **Authorise the management surface.** `ActuatorChainConfig.hardenedChain` with
   `/actuator/health` and `/actuator/info` permitted, `/actuator/**` behind `hasRole("ACTUATOR")`,
   `anyRequest().denyAll()` as the default, HTTP Basic for operators and CSRF left on.
5. **Delete the debug surfaces.** `spring.h2.console.enabled: false`, no `/api-docs/openapi.json` in the
   deployed artifact, `management.endpoint.shutdown.enabled: false`. If a break-glass shutdown is
   genuinely required, it goes on its own port behind the platform's access control.
6. **Trim `info`.** `app.name` and a version is enough for a dashboard; the internal SCM URL, branch and
   commit build a map of the estate and belong in the deployment record, not in an HTTP response.
7. **Test the negative.** CI asserts `404` for `/actuator/env` on the application port and `401` for
   `/actuator/heapdump` on the management port; a configuration change that re-exposes either fails.

## Detection

* Semgrep rule `actuator-all-endpoints-exposed` (YAML) flags `include: '*'` in any `*.yml`/`*.yaml`.
  `scripts/run_sast.sh` runs it; it also lists the actuator-related hits in its grep fallback.
* `scripts/run_dast_zap.sh` probes `/actuator`, `/actuator/env`, `/actuator/heapdump` and
  `/api-docs/openapi.json` on ports 8081-8096 and prints every `200` as `OPEN`. Against an unhardened
  range that list is the finding; against a hardened one it must be empty for the management paths.
* Grep the diff for `show-details: always`, `show-values: always`, `shutdown`, `h2:\s*console`,
  `include: '*'`, `management.server.port` and `permitAll`.
* Review the deployed `application.yml` next to `application-safe.yml`: if the deployed file is the one
  that ships with `include: '*'`, the safe profile is a file nobody starts.

## Where this appears in real reviews

A production `application.yml` that still carries `exposure.include: '*'` and `show-details: always`
because the monitoring team asked for "full health output"; the H2 console left enabled because it was
useful in a demo branch; an `openapi.json` in `static/` that keeps growing as internal and debug routes
are added; and a management surface that is protected by a security chain which, like
`ActuatorChainConfig.exposedChain`, permits everything. None of these is a code bug, which is exactly
why code review misses them and a configuration diff catches them.
