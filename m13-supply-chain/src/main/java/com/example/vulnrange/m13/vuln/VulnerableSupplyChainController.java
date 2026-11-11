package com.example.vulnrange.m13.vuln;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputFilter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * VULNERABLE (intentional): the module's dependency set is the vulnerability. PoC:
 * {@code attacks/13-supply-chain.sh}.
 */
@RestController
@RequestMapping("/vuln13")
public class VulnerableSupplyChainController {

    private static final Logger log = LoggerFactory.getLogger(VulnerableSupplyChainController.class);

    /** Maven coordinates of the two libraries this module ships on purpose. */
    private static final List<String[]> FLAGGED = List.of(
            new String[] {"commons-collections", "commons-collections"},
            new String[] {"com.alibaba", "fastjson"});

    /**
     * The inventory an SCA tool derives from {@code META-INF/maven/.../pom.properties}. Read it, then
     * compare with what your scanner reports: a scanner that says nothing about the versions listed
     * here is misconfigured or running with an outdated database.
     */
    @GetMapping("/dependency-inventory")
    public Map<String, Object> inventory() {
        List<Map<String, String>> libraries = new ArrayList<>();
        for (String[] coordinates : FLAGGED) {
            libraries.add(identify(coordinates[0], coordinates[1]));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("flaggedLibraries", libraries);
        out.put("gadgetClassesPresent", gadgetAvailability());
        out.put("note", "versions above must appear as findings in your SCA report");
        return out;
    }

    /**
     * VULNERABLE (shape): commons-collections 3.2.1 ships {@code InvokerTransformer}, the building
     * block of the classic deserialization chains. Here a transformer is serialised and deserialised
     * in-process to show that attacker-chosen classes get instantiated and their methods invoked;
     * chaining that into an exploit is deliberately out of scope for this range.
     */
    @PostMapping("/gadget/round-trip")
    @SuppressWarnings({"rawtypes", "unchecked"})
    public ResponseEntity<Map<String, Object>> gadgetRoundTrip(@RequestBody Map<String, String> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            org.apache.commons.collections.functors.InvokerTransformer transformer =
                    new org.apache.commons.collections.functors.InvokerTransformer(
                            body.getOrDefault("method", "toUpperCase"), new Class<?>[0], new Object[0]);

            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ObjectOutputStream out1 = new ObjectOutputStream(bytes)) {
                out1.writeObject(transformer);
            }
            String encoded = Base64.getEncoder().encodeToString(bytes.toByteArray());

            Object restored;
            try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
                restored = in.readObject(); // VULNERABLE: no filter, arbitrary classes
            }
            Object applied = ((org.apache.commons.collections.Transformer) restored)
                    .transform(body.getOrDefault("target", "gadget-primitive"));
            out.put("serializedPayloadBase64", encoded.length() + " bytes");
            out.put("restoredClass", restored.getClass().getName());
            out.put("reflectiveCallResult", String.valueOf(applied));
            out.put("whyItMatters", "an attacker picks the class and the method; you only have to readObject()");
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    /**
     * VULNERABLE: fastjson with {@code autoTypeSupport} enabled resolves {@code @type} against the
     * classpath. The payload below instantiates an application class and calls its setters — the exact
     * primitive the long line of fastjson autotype CVEs starts from.
     */
    @PostMapping("/parse-json")
    public Map<String, Object> parseWithFastjson(@RequestBody String json) {
        SideEffects.clear();
        try {
            com.alibaba.fastjson.parser.ParserConfig config = com.alibaba.fastjson.parser.ParserConfig.getGlobalInstance();
            // VULNERABLE: autotype is enabled by default in 1.2.24, resolving @type against the classpath.
            Object parsed = new com.alibaba.fastjson.parser.DefaultJSONParser(json, config).parse();
            return Map.of("parsedClass", parsed == null ? "null" : parsed.getClass().getName(),
                    "sideEffects", SideEffects.log());
        } catch (Exception e) {
            return Map.of("error", String.valueOf(e.getMessage()), "sideEffects", SideEffects.log());
        }
    }

    /** A filter would have stopped the round trip above; this shows the mitigation available in JDK 17+. */
    @PostMapping("/gadget/with-filter")
    public Map<String, Object> gadgetWithFilter(@RequestBody Map<String, String> body) {
        try {
            byte[] bytes = Base64.getDecoder().decode(body.getOrDefault("base64", ""));
            try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
                in.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                        "java.lang.String;java.lang.Number;!*"));
                return Map.of("restored", String.valueOf(in.readObject()));
            }
        } catch (Exception e) {
            return Map.of("rejected", true, "detail", e.getClass().getSimpleName());
        }
    }

    private static Map<String, String> identify(String groupId, String artifactId) {
        Map<String, String> info = new LinkedHashMap<>();
        info.put("groupId", groupId);
        info.put("artifactId", artifactId);
        String resource = "/META-INF/maven/" + groupId + "/" + artifactId + "/pom.properties";
        try (var in = VulnerableSupplyChainController.class.getResourceAsStream(resource)) {
            if (in == null) {
                info.put("version", "unknown (pom.properties not packaged)");
            } else {
                Properties properties = new Properties();
                properties.load(in);
                info.put("version", properties.getProperty("version", "unknown"));
            }
        } catch (Exception e) {
            info.put("version", "unreadable");
        }
        return info;
    }

    private static Map<String, Boolean> gadgetAvailability() {
        Map<String, Boolean> availability = new LinkedHashMap<>();
        for (String className : List.of(
                "org.apache.commons.collections.functors.InvokerTransformer",
                "org.apache.commons.collections.functors.ChainedTransformer",
                "org.apache.commons.collections.functors.ConstantTransformer")) {
            availability.put(className, classPresent(className));
        }
        return availability;
    }

    private static boolean classPresent(String className) {
        try {
            Class.forName(className, false, VulnerableSupplyChainController.class.getClassLoader());
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Records what attacker-supplied content caused to run (see fastjson autotype demo). */
    public static final class SideEffects {
        private static final List<String> LOG = Collections.synchronizedList(new ArrayList<>());

        private SideEffects() {
        }

        public static void record(String entry) {
            LOG.add(entry);
            log.info("side effect from untrusted payload: {}", entry);
        }

        public static List<String> log() {
            synchronized (LOG) {
                return List.copyOf(LOG);
            }
        }

        public static void clear() {
            LOG.clear();
        }
    }

    /** Target class for the fastjson autotype demo: a public setter is enough. */
    public static class AutotypeProbe {
        private String note;

        public void setNote(String note) {
            this.note = note;
            SideEffects.record("AutotypeProbe.setNote('" + note + "') called from @type payload");
        }

        public String getNote() {
            return note;
        }
    }
}
