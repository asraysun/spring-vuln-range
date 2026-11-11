package com.example.vulnrange.m11.vuln;

import java.util.List;

import com.example.vulnrange.m11.domain.SubscriberEntity;
import com.example.vulnrange.m11.domain.SubscriberRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * VULNERABLE (intentional): the database model is the API contract. PoC:
 * {@code attacks/11-data-exposure.sh}.
 */
@RestController
@RequestMapping("/vuln11")
public class VulnerableExposureController {

    private final SubscriberRepository repository;

    public VulnerableExposureController(SubscriberRepository repository) {
        this.repository = repository;
    }

    /**
     * VULNERABLE: entity serialised straight out. The response carries {@code passwordHash},
     * {@code refreshToken}, {@code internalRiskScore}, INN/SNILS and the ESPD token hash — none of
     * which were requested, all of which are now in a client, a proxy log and a browser cache.
     */
    @GetMapping("/subscribers/{id}")
    public SubscriberEntity subscriber(@PathVariable String id) {
        return repository.findById(id).orElseThrow(() -> new IllegalStateException("not found"));
    }

    /** VULNERABLE: whole table, no projection, no pagination. */
    @GetMapping("/subscribers")
    public List<SubscriberEntity> all() {
        return java.util.stream.StreamSupport.stream(repository.findAll().spliterator(), false).toList();
    }

    /** VULNERABLE: PII (e-mail) in the query string lands in access logs, referrer and caches. */
    @GetMapping("/subscribers/search")
    public List<SubscriberEntity> search(@RequestParam String email) {
        return repository.findByEmail(email);
    }

    /** VULNERABLE: access token as a query parameter — logged by every hop between client and server. */
    @GetMapping("/reports/{id}")
    public String report(@PathVariable String id, @RequestParam String accessToken) {
        return "{\"reportId\":\"" + id + "\",\"acceptedToken\":\"" + accessToken
                + "\",\"rows\":3,\"note\":\"the token was echoed and is now in the access log\"}";
    }

    /** VULNERABLE: "select any field" with no allow-list; {@code fields=passwordHash} works. */
    @GetMapping("/subscribers/{id}/export")
    public String export(@PathVariable String id,
                        @RequestParam(defaultValue = "*") String fields) {
        SubscriberEntity subscriber = repository.findById(id).orElseThrow(() -> new IllegalStateException("not found"));
        return "{\"id\":\"" + subscriber.getId() + "\",\"requestedFields\":\"" + fields
                + "\",\"passwordHash\":\"" + subscriber.getPasswordHash()
                + "\",\"refreshToken\":\"" + subscriber.getRefreshToken() + "\"}";
    }

    /** VULNERABLE: client controls the page size; {@code ?size=100000} is a self-inflicted outage. */
    @GetMapping("/subscribers/page")
    public List<SubscriberEntity> page(@RequestParam(defaultValue = "1000000") int size,
                                      @RequestParam(defaultValue = "0") int page) {
        int requestedSize = Math.clamp(size, 1, 1_000_000);
        return repository.findAll(org.springframework.data.domain.PageRequest.of(Math.max(page, 0), requestedSize))
                .getContent();
    }
}
