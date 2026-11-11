package com.example.vulnrange.m06.safe;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import com.example.vulnrange.m06.safe.dto.SessionSnapshot;
import com.example.vulnrange.m06.vuln.SideEffects;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;

/**
 * Reference implementation of checklist section 6.
 *
 * <p>Order of preference, from best to acceptable:
 * <ol>
 *   <li>do not deserialize object graphs from the network at all — exchange a schema-validated
 *       representation (JSON/Protobuf) and map it into your own types;</li>
 *   <li>if a binary format is unavoidable, apply a hard type allow-list plus depth/array/byte limits
 *       ({@link ObjectInputFilter}) and treat every violation as an attack, not a bad request;</li>
 *   <li>for XML, disable DTDs and external entity resolution, and never reuse a default parser
 *       configuration.</li>
 * </ol>
 *
 * <p>{@code SideEffects} is imported from the demo package only so that these endpoints can prove
 * nothing executed; production code has no business calling it.
 */
@RestController
@RequestMapping("/safe6")
public class SafeDeserializationController {

    private static final int MAX_SERIALIZED_BYTES = 64 * 1024;
    private static final int MAX_DEPTH = 8;
    private static final int MAX_ARRAY_LENGTH = 256;
    private static final int MAX_REFS = 1_000;

    private final ObjectMapper strictMapper = new ObjectMapper()
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    /**
     * Type allow-list plus resource limits. The allow-list is the part that stops gadget chains;
     * the limits are what stops memory/CPU exhaustion from a small request.
     */
    private static final ObjectInputFilter ALLOW_LIST = info -> {
        if (info.serialClass() == null) {
            // Array/length/depth/refs checks.
            if (info.depth() > MAX_DEPTH) {
                return ObjectInputFilter.Status.REJECTED;
            }
            if (info.arrayLength() > MAX_ARRAY_LENGTH) {
                return ObjectInputFilter.Status.REJECTED;
            }
            if (info.streamBytes() > MAX_SERIALIZED_BYTES) {
                return ObjectInputFilter.Status.REJECTED;
            }
            if (info.references() > MAX_REFS) {
                return ObjectInputFilter.Status.REJECTED;
            }
            return ObjectInputFilter.Status.UNDECIDED;
        }
        Class<?> allowed = info.serialClass();
        if (allowed == SessionSnapshot.class || allowed == String.class
                || allowed == Long.class || allowed == Integer.class
                || allowed.getPackageName().startsWith("java.time")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    };

    /** Same payload shape as the vulnerable endpoint, but the class list is closed. */
    @PostMapping("/session/import")
    public ResponseEntity<Map<String, Object>> importSession(@RequestBody Map<String, String> body) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(body.getOrDefault("base64", ""));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "payload is not base64"));
        }
        if (bytes.length > MAX_SERIALIZED_BYTES) {
            return ResponseEntity.badRequest().body(Map.of("error", "payload too large"));
        }
        try (ObjectInputStream in = new FilteringObjectInputStream(new ByteArrayInputStream(bytes))) {
            Object restored = in.readObject();
            if (!(restored instanceof SessionSnapshot snapshot)) {
                return ResponseEntity.badRequest().body(Map.of("error", "unexpected payload type"));
            }
            return ResponseEntity.ok(Map.of(
                    "restoredClass", snapshot.getClass().getName(),
                    "subscriptionId", String.valueOf(snapshot.getSubscriptionId()),
                    "sideEffects", SideEffects.log()));
        } catch (InvalidClassException e) {
            return ResponseEntity.status(415).body(Map.of("error", "class rejected by allow-list",
                    "detail", String.valueOf(e.getMessage())));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "payload rejected",
                    "detail", e.getClass().getSimpleName()));
        }
    }

    /** XStream with the deny-list restored and a closed type set. */
    @PostMapping(value = "/xml/xstream", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<Map<String, Object>> xstream(@RequestBody String xml) {
        XStream xstream = new XStream();
        xstream.addPermission(NoTypePermission.NONE);                       // deny everything first
        xstream.allowTypes(new Class<?>[] {SessionSnapshot.class});          // then allow exactly these
        xstream.omitField(SessionSnapshot.class, "asOfEpochSecond");         // fields you do not need
        try {
            Object restored = xstream.fromXML(xml);
            return ResponseEntity.ok(Map.of("restoredClass", restored.getClass().getName(),
                    "sideEffects", SideEffects.log()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "document rejected",
                    "detail", e.getClass().getSimpleName()));
        }
    }

    /** DTDs and external entities are refused before parsing begins. */
    @PostMapping(value = "/xml/parse", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<Map<String, Object>> parseXml(@RequestBody String xml) {
        try {
            Document document = hardenedFactory().newDocumentBuilder()
                    .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            return ResponseEntity.ok(Map.of("parsed", true,
                    "rootElement", document.getDocumentElement().getTagName(),
                    "text", document.getDocumentElement().getTextContent()));
        } catch (Exception e) {
            // A DOCTYPE here is a rejection, and a rejected request worth alerting on.
            return ResponseEntity.badRequest().body(Map.of("error", "document rejected",
                    "detail", e.getClass().getSimpleName()));
        }
    }

    /** Concrete target type, no polymorphic typing, unknown properties are an error. */
    @PostMapping(value = "/json/data", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> jsonData(@RequestBody String json) {
        try {
            SessionSnapshot snapshot = strictMapper.readValue(json, SessionSnapshot.class);
            return ResponseEntity.ok(Map.of("subscriptionId", String.valueOf(snapshot.getSubscriptionId()),
                    "plan", String.valueOf(snapshot.getPlan())));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid document",
                    "detail", e.getClass().getSimpleName()));
        }
    }

    static DocumentBuilderFactory hardenedFactory() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // The one switch that actually stops XXE: no DTD means no external entity, no billion laughs.
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        setIfSupported(factory, "http://xml.org/sax/features/external-general-entities", false);
        setIfSupported(factory, "http://xml.org/sax/features/external-parameter-entities", false);
        setIfSupported(factory, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory;
    }

    private static void setIfSupported(DocumentBuilderFactory factory, String feature, boolean value) {
        try {
            factory.setFeature(feature, value);
        } catch (Exception ignored) {
            // Parser does not implement the feature; disallow-doctype-decl above is the control.
        }
    }

    /** Allow-list of permitted class names for deserialization. */
    private static final Set<String> ALLOWED_CLASSES = Set.of(
            SessionSnapshot.class.getName(),
            String.class.getName(),
            Long.class.getName(),
            Integer.class.getName());

    /** Lightweight ObjectInputStream that enforces a type allow-list via resolveClass. */
    private static class FilteringObjectInputStream extends ObjectInputStream {
        FilteringObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String name = desc.getName();
            if (!ALLOWED_CLASSES.contains(name) && !name.startsWith("java.time.")) {
                throw new InvalidClassException(name, "Class rejected by allow-list");
            }
            return super.resolveClass(desc);
        }
    }
}
