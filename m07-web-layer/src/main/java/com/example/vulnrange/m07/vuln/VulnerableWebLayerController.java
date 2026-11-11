package com.example.vulnrange.m07.vuln;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
 * VULNERABLE (intentional): browser-facing functionality without CSRF, without security headers and
 * with raw output encoding. PoC: {@code attacks/07-web-layer.sh}.
 */
@Controller
@RequestMapping("/vuln7")
public class VulnerableWebLayerController {

    /** Stored "operator notes" rendered as raw HTML - stored XSS (CWE-79). */
    private final List<String> notes = Collections.synchronizedList(new ArrayList<>(List.of(
            "Subscription renewed automatically.")));

    /**
     * VULNERABLE: no CSRF token required for a state change that the browser authorises with its
     * session cookie. A form hosted anywhere (see docs) cancels the subscription of a logged-in user.
     */
    @PostMapping("/subscriptions/{id}/cancel")
    @ResponseBody
    public Map<String, Object> cancel(@PathVariable String id) {
        return Map.of("id", id, "status", "CANCELLED", "csrfTokenRequired", false);
    }

    /** VULNERABLE: reflected value rendered with th:utext (unescaped). */
    @GetMapping("/page")
    public String page(@RequestParam(defaultValue = "operator") String name, Model model) {
        model.addAttribute("name", name);
        model.addAttribute("notes", List.copyOf(notes));
        return "vuln-page";
    }

    /** VULNERABLE: stored payload rendered later, still unescaped. */
    @PostMapping(value = "/notes", consumes = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public Map<String, Object> addNote(@RequestBody String note) {
        notes.add(note);
        return Map.of("stored", notes.size());
    }

    /**
     * VULNERABLE: CORS echoes any origin with credentials on, so any site can read this response
     * with the victim's cookie.
     */
    @GetMapping("/profile")
    @ResponseBody
    public Map<String, Object> profile() {
        return Map.of("username", "alice", "email", "alice@example.invalid",
                "subscriptionId", "SUB-1001", "phone", "+7-000-000-0000");
    }

    /** VULNERABLE: page is frameable (no X-Frame-Options / CSP frame-ancestors) - clickjacking. */
    @GetMapping(value = "/clickjacking", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String clickjackingPage() {
        return """
                <!DOCTYPE html><html><head><meta charset="utf-8"><title>Cancel subscription</title></head>
                <body style="font-family:sans-serif">
                  <h2>Your ESPD subscription</h2>
                  <p>Click below to keep your current tariff:</p>
                  <button onclick="fetch('/vuln7/subscriptions/SUB-1001/cancel',{method:'POST'})
                          .then(()=>document.body.innerText='Done')">Keep tariff</button>
                </body></html>""";
    }

    /** VULNERABLE: user HTML returned with a text/html content type (self-XSS / stored payload host). */
    @GetMapping(value = "/preview", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String preview(@RequestParam(defaultValue = "hello") String fragment) {
        return "<html><body>" + fragment + "</body></html>";
    }

    /** VULNERABLE: sniffing allowed (no X-Content-Type-Options) on an HTML-capable response. */
    @GetMapping(value = "/upload-preview", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    @ResponseBody
    public ResponseEntity<byte[]> uploadPreview(@RequestParam(defaultValue = "<p>hello</p>") String body) {
        return ResponseEntity.ok(body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
