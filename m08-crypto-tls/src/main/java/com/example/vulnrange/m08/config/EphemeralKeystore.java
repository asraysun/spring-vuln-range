package com.example.vulnrange.m08.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Creates a single-use self-signed keystore for the local HTTPS listener.
 *
 * <p>Why this exists as code instead of a committed {@code .p12}: a keystore in a repository is a
 * credential, and "just the demo certificate" is how private keys end up in git history. The file
 * here lives in the temp directory, with a random per-start password, and is deleted on exit.
 */
@Component
public class EphemeralKeystore {

    private static final Logger log = LoggerFactory.getLogger(EphemeralKeystore.class);
    private static final String ALIAS = "vulnrange";

    private final Path path;
    private final char[] password;

    public EphemeralKeystore() {
        this.path = Path.of(System.getProperty("java.io.tmpdir"), "vulnrange-m08-keystore.p12");
        byte[] secret = new byte[24];
        new SecureRandom().nextBytes(secret);
        this.password = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(secret).toCharArray();
        generate();
        Runtime.getRuntime().addShutdownHook(new Thread(this::deleteQuietly));
    }

    public String path() {
        return path.toString();
    }

    public String password() {
        return new String(password);
    }

    public String alias() {
        return ALIAS;
    }

    private void generate() {
        try {
            Files.deleteIfExists(path);
            String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
            ProcessBuilder builder = new ProcessBuilder(keytool, "-genkeypair",
                    "-alias", ALIAS,
                    "-keyalg", "RSA", "-keysize", "2048",
                    "-sigalg", "SHA256withRSA",
                    // 1 day: a throw-away certificate must not outlive the process that needs it.
                    "-validity", "1",
                    "-dname", "CN=localhost, O=vulnrange-demo, C=RU",
                    "-ext", "SAN=dns:localhost,ip:127.0.0.1",
                    "-storetype", "PKCS12",
                    "-keystore", path.toString(),
                    // Password via env reference so it never appears in the process arguments.
                    "-storepass:env", "VPASS",
                    "-keypass:env", "VPASS",
                    "-noprompt");
            builder.environment().put("VPASS", new String(password));
            builder.redirectErrorStream(true);
            Process process = builder.start();
            boolean done = process.waitFor(30, TimeUnit.SECONDS);
            if (!done || process.exitValue() != 0) {
                log.warn("keystore generation did not finish cleanly (done={}, exit={})",
                        done, done ? process.exitValue() : "timeout");
            }
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("cannot generate the throw-away keystore; the HTTPS listener stays disabled: {}",
                    e.getMessage());
        }
    }

    private void deleteQuietly() {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // best effort
        }
    }
}
