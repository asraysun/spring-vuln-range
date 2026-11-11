package com.example.vulnrange.m05.vuln;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * VULNERABLE (intentional): every sink below interprets a client string as code. PoC:
 * {@code attacks/05-injection.sh}, narrative: {@code docs/05-injection.md}.
 *
 * <p>The two sinks that can affect the host process are gated behind explicit environment flags so
 * that starting the range never leaves an open command/type-resolution endpoint:
 * {@code VULNRANGE_ALLOW_EXEC}, {@code VULNRANGE_ALLOW_SPEL_TYPES}.
 */
@RestController
@RequestMapping("/vuln5")
public class VulnerableInjectionController {

    private static final Logger log = LoggerFactory.getLogger(VulnerableInjectionController.class);
    private static final boolean EXEC_ENABLED = "true".equalsIgnoreCase(System.getenv("VULNRANGE_ALLOW_EXEC"));
    private static final boolean SPEL_TYPES_ENABLED =
            "true".equalsIgnoreCase(System.getenv("VULNRANGE_ALLOW_SPEL_TYPES"));

    private final JdbcTemplate jdbc;
    private final ExpressionParser parser = new SpelExpressionParser();

    @PersistenceContext
    private EntityManager entityManager;

    public VulnerableInjectionController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * VULNERABLE: SQL injection through JDBC string concatenation (CWE-89).
     * {@code ' OR '1'='1} returns every row; a UNION against {@code integration_credentials} reads
     * the credentials table, because the application user can select from it.
     */
    @GetMapping("/subscriptions")
    public Map<String, Object> byEmail(@RequestParam String email) {
        String sql = "SELECT id, owner_username, plan, monthly_price FROM subscription "
                + "WHERE customer_email = '" + email + "'";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sql", sql);
        out.put("rows", jdbc.queryForList(sql));
        return out;
    }

    /** VULNERABLE: LIKE built by concatenation, wildcards not escaped (data leak + full table scan). */
    @GetMapping("/search")
    public Map<String, Object> search(@RequestParam String q) {
        String sql = "SELECT id, customer_email FROM subscription WHERE customer_email LIKE '%" + q + "%'";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sql", sql);
        out.put("rows", jdbc.queryForList(sql));
        return out;
    }

    /**
     * VULNERABLE: ORDER BY from the request. Identifiers cannot be bound as parameters, so the usual
     * "we use parameters everywhere" argument does not cover this line; blind extraction with
     * {@code CASE WHEN} works.
     */
    @GetMapping("/list")
    public Map<String, Object> list(@RequestParam(defaultValue = "created_at") String sort,
                                   @RequestParam(defaultValue = "asc") String dir) {
        String sql = "SELECT id, plan, created_at FROM subscription ORDER BY " + sort + " " + dir;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sql", sql);
        try {
            out.put("rows", jdbc.queryForList(sql));
        } catch (RuntimeException e) {
            // VULNERABLE: the database error text reaches the caller -> schema disclosure.
            out.put("error", String.valueOf(e.getMessage()));
        }
        return out;
    }

    /** VULNERABLE: JPQL assembled with concatenation ("it is not raw SQL, so it is safe"). */
    @GetMapping("/jpa")
    @Transactional(readOnly = true)
    public Map<String, Object> jpaNative(@RequestParam String plan) {
        String jpql = "SELECT s FROM SubscriptionEntity s WHERE s.plan = '" + plan + "'";
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("jpql", jpql);
        out.put("rows", entityManager.createQuery(jpql).getResultList().size() + " entities matched");
        return out;
    }

    /** VULNERABLE: native query through the EntityManager, same concatenation problem. */
    @GetMapping("/native")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> nativeQuery(@RequestParam String tenantId) {
        String sql = "SELECT id, owner_username FROM subscription WHERE tenant_id = '" + tenantId + "'";
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Object row : entityManager.createNativeQuery(sql).getResultList()) {
            Object[] cells = (Object[]) row;
            Map<String, Object> mapped = new LinkedHashMap<>();
            mapped.put("id", cells[0]);
            mapped.put("owner_username", cells[1]);
            rows.add(mapped);
        }
        return rows;
    }

    /**
     * VULNERABLE (structure): user input reaches the SpEL parser (CWE-917).
     *
     * <p>Default evaluation context here is <em>restricted</em>: property access on a fixed root
     * object only, so a request leaks object structure rather than executing code. Setting
     * {@code VULNRANGE_ALLOW_SPEL_TYPES=true} switches to a {@link StandardEvaluationContext} with
     * type references enabled, which is what an unpatched real-world service looks like — that mode
     * is code execution by definition, so it is opt-in and documented, never the default.
     */
    @GetMapping("/report")
    public Map<String, Object> report(@RequestParam String expr) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("expression", expr);
        Object root = new ReportRoot("ESPD-BASIC", new java.math.BigDecimal("990.00"), "T-100");
        try {
            if (SPEL_TYPES_ENABLED) {
                StandardEvaluationContext ctx = new StandardEvaluationContext(root);
                out.put("mode", "STANDARD_CONTEXT_TYPES_ENABLED (dangerous, opt-in)");
                out.put("result", String.valueOf(parser.parseExpression(expr).getValue(ctx)));
            } else {
                var ctx = org.springframework.expression.spel.support.SimpleEvaluationContext
                        .forReadOnlyDataBinding()
                        .withRootObject(root)
                        .build();
                out.put("mode", "SANDBOXED (property access only) — set VULNRANGE_ALLOW_SPEL_TYPES=true to see the unsandboxed shape");
                out.put("result", String.valueOf(parser.parseExpression(expr).getValue(ctx)));
            }
        } catch (Exception e) {
            out.put("error", "SpEL evaluation failed: " + e.getMessage());
            out.put("mode", SPEL_TYPES_ENABLED ? "STANDARD_CONTEXT_TYPES_ENABLED" : "SANDBOXED");
        }
        return out;
    }

    /**
     * VULNERABLE (structure): shell-composed command (CWE-78). Disabled unless
     * {@code VULNRANGE_ALLOW_EXEC=true}, because a reachable version of this method is arbitrary
     * command execution on the host and the range must not ship that switched on.
     */
    @PostMapping("/tools/ping")
    public ResponseEntity<Map<String, Object>> ping(@RequestParam String host) {
        if (!EXEC_ENABLED) {
            return ResponseEntity.status(403).body(Map.of(
                    "disabled", true,
                    "why", "this method builds 'sh -c \"ping -c 1 \" + host'; running it is arbitrary command execution",
                    "enable", "set VULNRANGE_ALLOW_EXEC=true if you really want to see it",
                    "vulnerableLine", "new ProcessBuilder(\"/bin/sh\", \"-c\", \"ping -c 1 \" + host)"));
        }
        List<String> lines = new ArrayList<>();
        try {
            Process process = new ProcessBuilder("/bin/sh", "-c", "ping -c 1 " + host).start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                reader.lines().limit(20).forEach(lines::add);
            }
            boolean finished = process.waitFor(5, TimeUnit.SECONDS);
            return ResponseEntity.ok(Map.of("exit", finished ? process.exitValue() : "timeout", "output", lines));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    /** VULNERABLE: raw client text written to the log (CRLF forging, oversized payloads, PII). */
    @PostMapping("/audit/message")
    public Map<String, Object> audit(@RequestParam String message) {
        log.info("audit: {}", message);
        return Map.of("logged", message);
    }

    /** Root object exposed to the SpEL demo. */
    public record ReportRoot(String plan, java.math.BigDecimal price, String tenantId) {
    }
}
