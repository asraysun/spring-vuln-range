package com.example.vulnrange.m16.vuln;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SAST fixtures — each method below is a pattern your static analysis is supposed to find. They exist
 * only so that "the SAST stage is green" becomes a falsifiable statement instead of a feeling.
 *
 * <p>Rules that should fire (FindSecBugs ids / Semgrep equivalents are listed in
 * {@code tools/semgrep/spring-security-rules.yml}):
 * SQL injection, path traversal, weak hash, permissive CORS/CSRF-style pattern, unsafe redirect,
 * hardcoded secret, log injection, insecure cookie, XML external entity parsing.
 *
 * <p>Endpoints are wired to nothing harmful: they are compiled, not exercised, and PoC scripts do not
 * call them.
 */
@RestController
@RequestMapping("/vuln16")
public class FlaggableSastFixtures {

    private final JdbcTemplate jdbc;

    public FlaggableSastFixtures(DataSource dataSource) {
        this.jdbc = new JdbcTemplate(dataSource);
    }

    /** FIXTURE 1 — SQL injection (FindSecBugs: SQL_INJECTION_JDBC / SEMGREP spring-sql-concatenation). */
    @GetMapping("/fixture/sql-injection")
    public String sqlInjection(@RequestParam String plan) {
        String sql = "SELECT id FROM subscription WHERE plan = '" + plan + "'";
        try {
            // expected finding: string concatenation inside a query built from a request parameter
            return jdbc.queryForList(sql).toString();
        } catch (RuntimeException e) {
            // The fixture table does not exist; the point is the sink, not the result.
            return "fixture executed an unsafe statement: " + sql;
        }
    }

    /** FIXTURE 2 — path traversal (FindSecBugs: PATH_TRAVERSAL_IN). */
    @GetMapping("/fixture/path-traversal")
    public String pathTraversal(@RequestParam String name) throws Exception {
        // expected finding: user input used to resolve a file path
        return java.nio.file.Files.readString(java.nio.file.Path.of("/tmp", name));
    }

    /** FIXTURE 3 — weak hash (FindSecBugs: WEAK_MESSAGE_DIGEST_MD5). */
    @GetMapping("/fixture/weak-hash")
    public String weakHash(@RequestParam String value) throws Exception {
        // expected finding: MD5 used for an integrity/security purpose
        return java.util.HexFormat.of().formatHex(
                java.security.MessageDigest.getInstance("MD5").digest(value.getBytes()));
    }

    /** FIXTURE 4 — open redirect (FindSecBugs: REDIRECT_HEADER_PARAMETER_DISCLOSURE / INSECURE_REDIRECT). */
    @GetMapping("/fixture/open-redirect")
    public String openRedirect(@RequestParam String url) {
        // expected finding: Location built from a request parameter
        return "redirect:" + url;
    }

    /** FIXTURE 5 — hardcoded credential (Semgrep: generic/secrets; gitleaks would catch the literal). */
    @GetMapping("/fixture/hardcoded-secret")
    public Map<String, String> hardcodedSecret() {
        // expected finding: credential material in source (placeholder value, never a real secret)
        String apiKey = "AKIAIOSFODNN7EXAMPLE";
        return Map.of("configured", apiKey.substring(0, 4) + "***");
    }

    /** FIXTURE 6 — log injection (FindSecBugs: CRLF_INJECTION_LOGS). */
    @PostMapping("/fixture/log-injection")
    public String logInjection(@RequestBody String message) {
        org.slf4j.LoggerFactory.getLogger(FlaggableSastFixtures.class).info("audit: {}", message);
        // expected finding: unsanitised request data written to the log
        return "logged";
    }

    /** FIXTURE 7 — XXE parsing without hardening (FindSecBugs: XML_DECODER, XXE_*). */
    @PostMapping("/fixture/xxe")
    public String xxe(@RequestBody String xml) throws Exception {
        // expected finding: default DocumentBuilderFactory, external entities enabled
        var builder = javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder();
        return builder.parse(new java.io.ByteArrayInputStream(xml.getBytes())).getDocumentElement().getTextContent();
    }

    /** FIXTURE 8 — JDBC connection string assembled from input (FindSecBugs: SQL_INJECTION_JDBC). */
    @GetMapping("/fixture/jdbc-url")
    public String jdbcUrlFromInput(@RequestParam String host) throws Exception {
        // expected finding: attacker-controlled host inside a JDBC url (also an SSRF/JNDI pattern)
        try (Connection ignored = DriverManager.getConnection("jdbc:postgresql://" + host + ":5432/espd")) {
            try (Statement statement = ignored.createStatement()) {
                return String.valueOf(statement.execute("SELECT 1"));
            }
        } catch (Exception e) {
            return "connection refused (fixture is not expected to connect)";
        }
    }
}
