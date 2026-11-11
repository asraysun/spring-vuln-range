package com.example.vulnrange.m07.safe;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Reference implementation of checklist section 7. Same business functionality, with the three
 * browser-side controls in place.
 */
@Controller
@RequestMapping("/safe7")
public class SafeWebLayerController {

    private final List<String> notes = Collections.synchronizedList(new ArrayList<>(List.of(
            "Subscription renewed automatically.")));

    /**
     * Token endpoint for SPA/CLI clients: the token is also delivered in the {@code XSRF-TOKEN}
     * cookie, and the state-changing call must send it back in {@code X-XSRF-TOKEN}.
     */
    @GetMapping("/csrf")
    @ResponseBody
    public Map<String, Object> csrf(HttpServletRequest request) {
        Object token = request.getAttribute(CsrfToken.class.getName());
        CsrfToken csrfToken;
        if (token instanceof CsrfToken ct) {
            csrfToken = ct;
        } else if (token instanceof java.util.function.Supplier<?> supplier) {
            csrfToken = (CsrfToken) supplier.get();
        } else {
            return Map.of("error", "csrf token unavailable");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("headerName", csrfToken.getHeaderName());
        out.put("parameterName", csrfToken.getParameterName());
        out.put("token", csrfToken.getToken());
        out.put("usage", "send the token in the header above together with the XSRF-TOKEN cookie");
        return out;
    }

    /** State change that requires a CSRF token; without one Spring Security answers 403. */
    @PostMapping("/subscriptions/{id}/cancel")
    @ResponseBody
    public Map<String, Object> cancel(@PathVariable String id) {
        return Map.of("id", id, "status", "CANCELLED", "csrfTokenRequired", true);
    }

    /** Same template shape, but values are emitted with th:text (escaped). */
    @GetMapping("/page")
    public String page(@RequestParam(defaultValue = "operator") String name, Model model) {
        model.addAttribute("name", escapeHtml(name));
        model.addAttribute("notes", List.copyOf(notes));
        return "safe-page";
    }

    /** Notes are stored as text and rendered as text; markup never becomes markup. */
    @PostMapping(value = "/notes", consumes = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public Map<String, Object> addNote(@RequestBody String note) {
        String cleaned = note.length() > 500 ? note.substring(0, 500) : note;
        notes.add(cleaned);
        return Map.of("stored", notes.size());
    }

    /** Credentialed CORS is granted only to the allow-listed origin (see WebLayerSecurityConfig). */
    @GetMapping("/profile")
    @ResponseBody
    public Map<String, Object> profile() {
        return Map.of("username", "alice", "email", "alice@example.invalid",
                "subscriptionId", "SUB-1001");
    }

    /**
     * Self-inspection for CI: reports the security headers this very response carries, so an
     * integration test can assert on them without parsing a browser.
     */
    @GetMapping("/headers-selftest")
    @ResponseBody
    public Map<String, String> headersSelftest(
            jakarta.servlet.http.HttpServletResponse response) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (String name : List.of("Content-Security-Policy", "X-Content-Type-Options",
                "X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security",
                "Cache-Control", "Permissions-Policy")) {
            String value = response.getHeader(name);
            if (value != null) {
                headers.put(name, value);
            }
        }
        return headers;
    }

    private static String escapeHtml(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}
