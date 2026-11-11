package com.example.vulnrange.m03.safe;

import java.util.Arrays;

/**
 * A secret that is safe to pass around the code base:
 *
 * <ul>
 *   <li>{@link #toString()} never reveals material — a logged or traced handle is not a leak;</li>
 *   <li>{@link #close()} zeroes the backing array, so the value does not linger in the heap;</li>
 *   <li>material is only exposed through {@link #use(java.util.function.Function)}, which zeroes
 *       after the callback returns where the platform allows it.</li>
 * </ul>
 *
 * <p>Prefer char[]/byte[] over {@code String} for key material: {@code String} is interned and
 * cannot be erased, which is why a "password" field in a DTO is a standing weakness.
 */
public final class SecretHandle implements AutoCloseable {

    private final byte[] material;
    private final String source;

    public SecretHandle(byte[] material, String source) {
        this.material = material.clone();
        this.source = source;
    }

    /** Runs {@code action} with a copy of the material and wipes the copy afterwards. */
    public <T> T use(java.util.function.Function<byte[], T> action) {
        byte[] copy = material.clone();
        try {
            return action.apply(copy);
        } finally {
            Arrays.fill(copy, (byte) 0);
        }
    }

    public int length() {
        return material.length;
    }

    /** Where the value came from (env var name, Vault path) - metadata, not material. */
    public String source() {
        return source;
    }

    /** First 2 and last 2 characters plus length: enough to tell two secrets apart in an audit. */
    public String fingerprint() {
        if (material.length < 8) {
            return "len=" + material.length + " ***";
        }
        String value = new String(material, java.nio.charset.StandardCharsets.UTF_8);
        return "len=" + material.length + " " + value.substring(0, 2) + "..." + value.substring(value.length() - 2);
    }

    @Override
    public void close() {
        Arrays.fill(material, (byte) 0);
    }

    @Override
    public String toString() {
        return "SecretHandle{source=" + source + ", " + fingerprint() + "}";
    }
}
