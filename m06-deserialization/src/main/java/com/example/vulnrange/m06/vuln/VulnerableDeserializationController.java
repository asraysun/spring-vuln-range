package com.example.vulnrange.m06.vuln;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.AnyTypePermission;
import jakarta.annotation.PostConstruct;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;

/**
 * VULNERABLE (intentional): four deserialization sinks, each of which hands control of object
 * creation to the request body. PoC: {@code attacks/06-deserialization.sh}.
 */
@RestController
@RequestMapping("/vuln6")
public class VulnerableDeserializationController {

    private final ObjectMapper looseMapper = new ObjectMapper();

    public VulnerableDeserializationController() {
        // VULNERABLE: polymorphic typing with a validator that accepts any subtype. The payload
        // decides which class is instantiated.
        looseMapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance,
                ObjectMapper.DefaultTyping.NON_FINAL);
    }

    /** Marker file so the XXE PoC has something self-contained to read back. */
    @PostConstruct
    void writeMarkerFile() {
        try {
            Files.writeString(markerFile(), """
                    VULNRANGE-M06-XXE-MARKER
                    synthetic document content - not a real secret, not real PII
                    line-2: if you can read this, external entities are being resolved
                    """);
        } catch (IOException ignored) {
            // demo helper only
        }
    }

    public static Path markerFile() {
        return Path.of(System.getProperty("java.io.tmpdir"), "vulnrange-m06-marker.txt").toAbsolutePath();
    }

    /** Convenience for the PoC: a well-formed serialized object the attacker can mutate. */
    @GetMapping("/session/example")
    public Map<String, Object> exampleSession() throws IOException {
        Map<Probe, String> session = new HashMap<>();
        Probe probe = new Probe();
        probe.setNote("pre-auth-cart");
        session.put(probe, "shopping-cart");

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(session);
        }
        SideEffects.clear();
        return Map.of(
                "base64", Base64.getEncoder().encodeToString(bytes.toByteArray()),
                "note", "restore it with POST /vuln6/session/import; edit the bytes and code still runs",
                "sideEffectsFromThisGeneration", SideEffects.log());
    }

    /**
     * VULNERABLE: Java deserialization of untrusted bytes (CWE-502) with no type filter and no size
     * limit. Any class on the classpath can be instantiated, and its {@code readObject}/
     * {@code hashCode}/{@code equals} run, by whoever controls these bytes.
     */
    @PostMapping("/session/import")
    public ResponseEntity<Map<String, Object>> importSession(@RequestBody Map<String, String> body) {
        String payload = body.getOrDefault("base64", "");
        SideEffects.clear();
        byte[] bytes = Base64.getDecoder().decode(payload);
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            Object restored = in.readObject();
            return ResponseEntity.ok(Map.of(
                    "restoredClass", restored.getClass().getName(),
                    "sideEffects", SideEffects.log()));
        } catch (IOException | RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage()),
                    "sideEffects", SideEffects.log()));
        } catch (ClassNotFoundException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "class not found",
                    "sideEffects", SideEffects.log()));
        }
    }

    /**
     * VULNERABLE: XStream without type permissions. {@code NoTypePermission.NONE} explicitly removes
     * the default deny-list, so the document root may name any class on the classpath.
     */
    @PostMapping(value = "/xml/xstream", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<Map<String, Object>> xstream(@RequestBody String xml) {
        XStream xstream = new XStream();
        xstream.addPermission(new com.thoughtworks.xstream.security.AnyTypePermission()); // VULNERABLE: allow any class
        SideEffects.clear();
        try {
            Object restored = xstream.fromXML(xml);
            return ResponseEntity.ok(Map.of("restoredClass", restored.getClass().getName(),
                    "sideEffects", SideEffects.log()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage()),
                    "sideEffects", SideEffects.log()));
        }
    }

    /**
     * VULNERABLE: XXE (CWE-611). {@link DocumentBuilderFactory} resolves external entities by
     * default, so {@code <!ENTITY x SYSTEM "file:///...">} reads local files, and an
     * {@code http://} entity turns the parser into an outbound request origin (SSRF).
     */
    @PostMapping(value = "/xml/xxe", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<Map<String, Object>> xxe(@RequestBody String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // No hardening flags at all - this is the default, and the default is unsafe.
            Document document = factory.newDocumentBuilder().parse(
                    new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            String text = document.getDocumentElement().getTextContent();
            return ResponseEntity.ok(Map.of("parsed", true, "text", text));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    /** VULNERABLE: polymorphic JSON — the payload names the class, Jackson instantiates it. */
    @PostMapping(value = "/json/polymorphic", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> polymorphicJson(@RequestBody String json) {
        SideEffects.clear();
        try {
            Object restored;
            // Handle both @class (PROPERTY) and array-form (WRAPPER_ARRAY) type references
            if (json.trim().startsWith("{")) {
                // Object form: {"@class":"com.example.Foo", ...}
                com.fasterxml.jackson.databind.JsonNode node = looseMapper.readTree(json);
                if (node.has("@class")) {
                    String className = node.get("@class").asText();
                    Class<?> clazz = Class.forName(className);
                    // Use a separate mapper without default typing to deserialize the payload
                    ObjectMapper strictMapper = new ObjectMapper();
                    strictMapper.disable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
                    restored = strictMapper.convertValue(node, clazz);
                } else {
                    restored = looseMapper.readValue(json, Object.class);
                }
            } else {
                restored = looseMapper.readValue(json, Object.class);
            }
            return ResponseEntity.ok(Map.of("restoredClass", restored.getClass().getName(),
                    "sideEffects", SideEffects.log()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage()),
                    "sideEffects", SideEffects.log()));
        }
    }

    @GetMapping("/side-effects")
    public Map<String, Object> sideEffects() {
        return Map.of("count", SideEffects.count(), "entries", SideEffects.log(),
                "markerFile", String.valueOf(markerFile()));
    }
}
