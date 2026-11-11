package com.example.vulnrange.m11.safe;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.example.vulnrange.m11.domain.SubscriberEntity;
import com.example.vulnrange.m11.domain.SubscriberRepository;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reference implementation of checklist section 11. The API surface is a deliberate, reviewed
 * contract: no entity ever leaves the service, identifiers stay out of URLs, and the page size is
 * the server's decision.
 */
@Validated
@RestController
@RequestMapping("/safe11")
public class SafeExposureController {

    private static final int MAX_PAGE_SIZE = 100;

    /**
     * Response contract. Everything absent here is absent from the wire: no hash, no token, no risk
     * score, no INN/SNILS. Additions to the entity do not automatically become API output.
     */
    public record SubscriberView(String id, String username, String maskedEmail, String primaryPlan) {
    }

    public record SearchRequest(@Email @Size(max = 254) String email) {
    }

    private final SubscriberRepository repository;

    public SafeExposureController(SubscriberRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/subscribers/{id}")
    public ResponseEntity<SubscriberView> subscriber(@PathVariable String id) {
        return repository.findById(id)
                .map(SafeExposureController::toView)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/subscribers")
    public Map<String, Object> page(@RequestParam(defaultValue = "0") int page,
                                   @RequestParam(defaultValue = "20") int size) {
        int limited = Math.clamp(size, 1, MAX_PAGE_SIZE);
        var result = repository.findAll(PageRequest.of(Math.max(page, 0), limited));
        return Map.of(
                "items", result.getContent().stream().map(SafeExposureController::toView).toList(),
                "page", result.getNumber(),
                "size", result.getSize(),
                "total", result.getTotalElements(),
                "maxPageSize", MAX_PAGE_SIZE);
    }

    /** PII travels in the request body: not in access logs, not in Referer, not in browser history. */
    @PostMapping("/subscribers/search")
    public List<SubscriberView> search(@RequestBody @Validated SearchRequest request) {
        return repository.findByEmail(request.email()).stream()
                .map(SafeExposureController::toView)
                .toList();
    }

    /** Credential in a header, report id in the path; nothing sensitive in the URL. */
    @GetMapping("/reports/{id}")
    public ResponseEntity<Map<String, Object>> report(@PathVariable String id,
                                                     @RequestHeader(value = "Authorization", required = false) String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(Map.of("error", "missing bearer token"));
        }
        return ResponseEntity.ok(Map.of("reportId", id, "rows", 3,
                "note", "the token was never echoed and never appeared in the URL"));
    }

    /** Field selection is an allow-list, and the allow-list is a projection, not a filter. */
    @GetMapping("/subscribers/{id}/export")
    public ResponseEntity<?> export(@PathVariable String id,
                                   @RequestParam(defaultValue = "username,primaryPlan") String fields) {
        List<String> allowed = List.of("id", "username", "maskedEmail", "primaryPlan");
        List<String> requested = List.of(fields.split(","));
        List<String> rejected = requested.stream().filter(f -> !allowed.contains(f)).toList();
        if (!rejected.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "field is not exportable", "rejected", rejected, "allowed", allowed));
        }
        return repository.findById(id)
                .<ResponseEntity<?>>map(subscriber -> {
                    SubscriberView view = toView(subscriber);
                    Map<String, Object> body = new LinkedHashMap<>();
                    if (requested.contains("id")) {
                        body.put("id", view.id());
                    }
                    if (requested.contains("username")) {
                        body.put("username", view.username());
                    }
                    if (requested.contains("maskedEmail")) {
                        body.put("maskedEmail", view.maskedEmail());
                    }
                    if (requested.contains("primaryPlan")) {
                        body.put("primaryPlan", view.primaryPlan());
                    }
                    return ResponseEntity.ok(body);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** Contract self-inspection: what this API is willing to say about a subscriber. */
    @GetMapping("/selftest")
    public Map<String, Object> selftest() {
        return Map.of(
                "exposedFields", List.of("id", "username", "maskedEmail", "primaryPlan"),
                "neverExposed", List.of("passwordHash", "refreshToken", "internalRiskScore",
                        "gdprErasureRequested", "inn", "snils", "espdTokenHash", "phone"),
                "paginationMaxPageSize", MAX_PAGE_SIZE,
                "piiInQueryParameters", false,
                "credentialsInQueryParameters", false);
    }

    private static SubscriberView toView(SubscriberEntity subscriber) {
        String plan = subscriber.getSubscriptions().isEmpty()
                ? "NONE"
                : subscriber.getSubscriptions().get(0).getPlan();
        return new SubscriberView(subscriber.getId(), subscriber.getUsername(),
                maskEmail(subscriber.getEmail()), plan);
    }

    /** a***e@example.invalid: enough for support conversations, useless for identity theft. */
    private static String maskEmail(String email) {
        if (email == null) {
            return null;
        }
        int at = email.indexOf('@');
        if (at <= 1) {
            return "***";
        }
        return email.charAt(0) + "***" + email.charAt(at - 1) + email.substring(at);
    }
}
