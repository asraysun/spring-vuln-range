package com.example.vulnrange.m03.safe;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Reference secret resolution order:
 *
 * <ol>
 *   <li>a file mounted by the Vault Agent / Kubernetes secret volume — preferred, because nothing
 *       sensitive ends up in {@code /proc/&lt;pid&gt;/environ}, {@code ps}, crash dumps or CI logs;</li>
 *   <li>an environment variable injected by the platform — acceptable, and never defaulted to a
 *       literal in the repository;</li>
 *   <li>otherwise: fail to start. A service without its credential must not come up with a
 *       developer's value.</li>
 * </ol>
 */
@Component
public class VaultFileSecretProvider {

    private static final Logger log = LoggerFactory.getLogger(VaultFileSecretProvider.class);

    private final String fileSecretsDir;
    private final String envVarName;
    private final String demoSecret;

    public VaultFileSecretProvider(
            @Value("${vulnrange.safe.file-secrets-dir:}") String fileSecretsDir,
            @Value("${vulnrange.safe.env-var-name:RANGE_M03_ESPD_API_KEY}") String envVarName,
            @Value("${vulnrange.safe.demo-secret:}") String demoSecret) {
        this.fileSecretsDir = fileSecretsDir;
        this.envVarName = envVarName;
        this.demoSecret = demoSecret;
    }

    public SecretHandle resolve(String name) {
        if (fileSecretsDir != null && !fileSecretsDir.isBlank()) {
            Path candidate = Path.of(fileSecretsDir).resolve(name).normalize();
            // Defence against a name like "../../etc/passwd" if name ever comes from outside.
            if (!candidate.startsWith(Path.of(fileSecretsDir).toAbsolutePath().normalize())
                    && !candidate.startsWith(Path.of(fileSecretsDir).normalize())) {
                throw new IllegalArgumentException("secret name escapes the mounted secret directory");
            }
            if (Files.isRegularFile(candidate)) {
                try {
                    byte[] bytes = Files.readAllBytes(candidate);
                    return new SecretHandle(trim(bytes), "file:" + candidate.getFileName());
                } catch (IOException e) {
                    throw new UncheckedIOException("cannot read mounted secret " + name, e);
                }
            }
        }
        String fromEnv = System.getenv(envVarName);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return new SecretHandle(fromEnv.getBytes(StandardCharsets.UTF_8), "env:" + envVarName);
        }
        // Fail closed and loudly; do not substitute a repository default.
        // A demo secret is only used when explicitly configured — it is never compiled into the jar.
        if (demoSecret != null && !demoSecret.isBlank()) {
            log.warn("no real secret available (file={}, env:{}); using demo secret for local runs", fileSecretsDir, envVarName);
            return new SecretHandle(demoSecret.getBytes(StandardCharsets.UTF_8), "demo");
        }
        log.error("secret '{}' is not available (checked mounted dir and env:{})", name, envVarName);
        throw new IllegalStateException("required secret missing: " + name);
    }

    private static byte[] trim(byte[] bytes) {
        int end = bytes.length;
        while (end > 0 && (bytes[end - 1] == '\n' || bytes[end - 1] == '\r' || bytes[end - 1] == ' ')) {
            end--;
        }
        byte[] out = new byte[end];
        System.arraycopy(bytes, 0, out, 0, end);
        return out;
    }
}
