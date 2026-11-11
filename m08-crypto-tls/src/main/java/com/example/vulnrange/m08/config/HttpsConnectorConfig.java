package com.example.vulnrange.m08.config;

import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;

/**
 * Adds a second, HTTPS-only connector so that TLS client behaviour can be compared against a real
 * handshake on the same application (see {@code POST /vuln8/fetch-https} vs
 * {@code POST /safe8/fetch-https}).
 */
@Configuration
public class HttpsConnectorConfig {

    private static final Logger log = LoggerFactory.getLogger(HttpsConnectorConfig.class);

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> httpsConnector(EphemeralKeystore keystore,
                                                                            @Value("${vulnrange.https.port:8443}") int httpsPort) {
        return factory -> {
            if (!Files.isRegularFile(Path.of(keystore.path()))) {
                log.warn("no throw-away keystore available; HTTPS listener on {} is disabled", httpsPort);
                return;
            }
            Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
            connector.setScheme("https");
            connector.setSecure(true);
            connector.setPort(httpsPort);
            Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
            // Additional connectors do not inherit server.address: bind them explicitly, or the
            // "loopback only" promise of this range silently breaks on the HTTPS port.
            protocol.setProperty("address", "127.0.0.1");
            protocol.setSSLEnabled(true);
            // Tomcat 10.x: keystore config moved to SSLHostConfig API.
            SSLHostConfig sslHostConfig = new SSLHostConfig();
            SSLHostConfigCertificate cert = new SSLHostConfigCertificate(
                    sslHostConfig, SSLHostConfigCertificate.Type.UNDEFINED);
            cert.setCertificateKeystoreFile(keystore.path());
            cert.setCertificateKeystoreType("PKCS12");
            cert.setCertificateKeystorePassword(keystore.password());
            // Alias is optional; Tomcat uses the first certificate if not specified.
            sslHostConfig.addCertificate(cert);
            connector.addSslHostConfig(sslHostConfig);
            // Modern minimum: no TLSv1 / TLSv1.1, no export or CBC-sha1 legacy suites.
            protocol.setProperty("sslProtocol", "TLS");
            protocol.setProperty("sslEnabledProtocols", "TLSv1.3,TLSv1.2");
            factory.addAdditionalTomcatConnectors(connector);
            log.info("HTTPS listener for the TLS demos: https://127.0.0.1:{}", httpsPort);
        };
    }
}
