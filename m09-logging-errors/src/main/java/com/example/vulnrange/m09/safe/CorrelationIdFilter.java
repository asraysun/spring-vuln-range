package com.example.vulnrange.m09.safe;

import java.io.IOException;
import java.util.regex.Pattern;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Correlation id for every request: returned to the caller, put in the MDC so all log lines of one
 * request can be joined, and never derived from client input when the header is absent.
 *
 * <p>Same idea, other half: the masking helpers below are what keeps credentials and PII out of the
 * log pipeline in the first place.
 */
@Component
@Order(1)
public class CorrelationIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Correlation-Id";
    public static final String MDC_KEY = "cid";
    private static final Pattern CLIENT_ID = Pattern.compile("^[A-Za-z0-9._-]{1,64}$");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String incoming = request.getHeader(HEADER);
        String correlationId = incoming != null && CLIENT_ID.matcher(incoming).matches()
                ? incoming
                : java.util.UUID.randomUUID().toString();
        // Bound the value that goes into a log pattern: a hostile header must not be able to
        // inject line breaks or huge payloads into the log stream.
        MDC.put(MDC_KEY, correlationId);
        response.setHeader(HEADER, correlationId);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }

    /** Masks credential-shaped values before they are logged. */
    public static String maskSecrets(String message) {
        if (message == null) {
            return null;
        }
        return message
                .replaceAll("(?i)(bearer\\s+)[A-Za-z0-9._\\-]+", "$1***")
                .replaceAll("(?i)(\"?(password|secret|token|apiKey|api_key)\"?\\s*[:=]\\s*\")[^\"]+", "$1***")
                // PAN: keep the first six digits (BIN) only where a BIN is genuinely needed.
                .replaceAll("\\b(?:\\d[ -]*?){13,19}\\b", "[card-number-masked]");
    }

    /** E-mail and identifier masking for audit lines. */
    public static String maskIdentity(String value) {
        if (value == null || value.isBlank()) {
            return "***";
        }
        int at = value.indexOf('@');
        if (at > 1) {
            return value.charAt(0) + "***" + value.substring(at);
        }
        return value.length() <= 3 ? "***" : value.substring(0, 2) + "***";
    }

    /** Neutralises log-forging characters (CR, LF, NUL, tab) and bounds the length. */
    public static String sanitiseForLog(String value, int maxLength) {
        String cleaned = value == null ? "" : value.replaceAll("[\\r\\n\\t\\u0000]", "_");
        return cleaned.length() <= maxLength ? cleaned : cleaned.substring(0, maxLength) + "…";
    }
}
