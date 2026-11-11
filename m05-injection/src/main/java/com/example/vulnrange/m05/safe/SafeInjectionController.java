package com.example.vulnrange.m05.safe;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import com.example.vulnrange.m05.domain.SubscriptionEntity;
import com.example.vulnrange.m05.domain.SubscriptionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * Reference implementation of checklist section 5. Data is data, names are names, code is code —
 * and the three never meet in the same string.
 */
@Validated
@RestController
@RequestMapping("/safe5")
public class SafeInjectionController {

    private static final Logger log = LoggerFactory.getLogger(SafeInjectionController.class);
    private static final Pattern SAFE_HOSTNAME = Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?$");
    private static final Pattern SAFE_TENANT = Pattern.compile("^T-\\d{3}$");
    private static final Pattern SAFE_EMAIL = Pattern.compile("^[^\\s@\"']{1,64}(@[A-Za-z0-9.-]{1,180})?$");
    private static final List<String> SORTABLE = List.of("id", "plan", "created_at", "monthly_price");

    /** Only pre-approved expressions may be evaluated; the request selects one by key. */
    private static final Map<String, String> EXPRESSION_REGISTRY = Map.of(
            "priceWithVat", "price * 1.20",
            "planLabel", "'Tariff: ' + plan",
            "isTrial", "price == 0");

    private final JdbcTemplate jdbc;
    private final SubscriptionRepository repository;
    private final ExpressionParser parser = new SpelExpressionParser();

    public SafeInjectionController(JdbcTemplate jdbc, SubscriptionRepository repository) {
        this.jdbc = jdbc;
        this.repository = repository;
    }

    /** Bind every value; validate shape before the query is even built. */
    @GetMapping("/subscriptions")
    public Map<String, Object> byEmail(@RequestParam String email) {
        if (!SAFE_EMAIL.matcher(email).matches() || email.length() > 254) {
            return Map.of("rejected", "unexpected email shape", "rows", List.of());
        }
        String sql = "SELECT id, owner_username, plan, monthly_price FROM subscription WHERE customer_email = ?";
        return Map.of("parameters", List.of(email), "rows", jdbc.queryForList(sql, email));
    }

    /** LIKE with bound parameter, explicit ESCAPE and escaped wildcards. */
    @GetMapping("/search")
    public Map<String, Object> search(@RequestParam String q) {
        if (q.isBlank() || q.length() > 64) {
            return Map.of("rejected", "search term must be 1..64 characters", "rows", List.of());
        }
        String escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        String sql = "SELECT id, customer_email FROM subscription WHERE customer_email LIKE ? ESCAPE '\\'";
        return Map.of("rows", jdbc.queryForList(sql, "%" + escaped + "%"));
    }

    /** Identifiers resolved from an allow-list: they can never be bound as parameters. */
    @GetMapping("/list")
    public Map<String, Object> list(@RequestParam(defaultValue = "created_at") String sort,
                                   @RequestParam(defaultValue = "desc") String dir) {
        String column = SORTABLE.stream().filter(c -> c.equalsIgnoreCase(sort)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("unknown sort column"));
        String direction = "asc".equalsIgnoreCase(dir) ? "ASC" : "DESC";
        String sql = "SELECT id, plan, created_at FROM subscription ORDER BY " + column + " " + direction;
        return Map.of("rows", jdbc.queryForList(sql), "sortBy", column, "direction", direction);
    }

    /** Spring Data with named parameters: the query text is constant. */
    @GetMapping("/jpa")
    public List<SubscriptionEntity> jpa(@RequestParam String plan, @RequestParam String tenantId) {
        if (!SAFE_TENANT.matcher(tenantId).matches() || plan.length() > 32) {
            return List.of();
        }
        return repository.findByPlanAndTenant(plan, tenantId);
    }

    /**
     * Expressions come from a registry maintained by developers; a request can only choose a key.
     * Even then evaluation runs in a read-only context without type references.
     */
    @GetMapping("/report")
    public Map<String, Object> report(@RequestParam String template) {
        String expression = EXPRESSION_REGISTRY.get(template);
        if (expression == null) {
            return Map.of("error", "unknown template", "allowed", EXPRESSION_REGISTRY.keySet());
        }
        Object root = new ReportRoot("ESPD-BASIC", new BigDecimal("990.00"), "T-100");
        var ctx = SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(root).build();
        return Map.of("template", template, "result", String.valueOf(parser.parseExpression(expression).getValue(ctx)));
    }

    /**
     * No shell, no concatenation: the host is validated, resolved, and passed as a single argv
     * element. Even a hostile value can only ever be an argument to {@code ping}.
     */
    @PostMapping("/tools/ping")
    public ResponseEntity<Map<String, Object>> ping(@RequestParam String host) {
        if (!SAFE_HOSTNAME.matcher(host).matches()) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid host"));
        }
        try {
            InetAddress address = InetAddress.getByName(host);
            Process process = new ProcessBuilder("ping", "-c", "1", address.getHostAddress())
                    .redirectErrorStream(true)
                    .start();
            List<String> lines = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                reader.lines().limit(20).forEach(lines::add);
            }
            boolean finished = process.waitFor(5, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return ResponseEntity.status(504).body(Map.of("error", "ping timed out"));
            }
            return ResponseEntity.ok(Map.of("resolved", address.getHostAddress(),
                    "exit", process.exitValue(), "output", lines));
        } catch (UnknownHostException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "host does not resolve"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "ping failed"));
        }
    }

    /** Log lines are structured: CRLF removed, length bounded, no raw credential material. */
    @PostMapping("/audit/message")
    public Map<String, Object> audit(@RequestParam String message) {
        String sanitised = message.replaceAll("[\\r\\n\\t]", "_");
        if (sanitised.length() > 200) {
            sanitised = sanitised.substring(0, 200) + "…";
        }
        log.info("audit event: {}", sanitised);
        return Map.of("stored", true, "length", sanitised.length());
    }

    public record ReportRoot(String plan, BigDecimal price, String tenantId) {
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "invalid request"));
    }
}
