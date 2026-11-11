package com.example.vulnrange.m08.vuln;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;

/**
 * VULNERABLE (intentional): the two TLS shortcuts that turn "we use HTTPS" into "we use HTTPS for
 * the packet capture". Both show up in real code reviews as {@code // TODO remove before release}.
 *
 * <ul>
 *   <li>a {@link X509TrustManager} that accepts every chain, so any certificate is trusted and an
 *       on-path attacker can present their own;</li>
 *   <li>a {@link HostnameVerifier} that returns {@code true}, so a certificate for another host is
 *       also accepted.</li>
 * </ul>
 */
public final class InsecureTlsClients {

    private InsecureTlsClients() {
    }

    /** VULNERABLE: accepts any certificate, performs no chain or validity checks. */
    public static final X509TrustManager TRUST_EVERYTHING = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // VULNERABLE: no verification at all.
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // VULNERABLE: no verification at all.
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    /** VULNERABLE: hostname is never compared to the certificate SAN/CN. */
    public static final HostnameVerifier ACCEPT_ANY_HOSTNAME = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    /** Builds a RestTemplate with both controls disabled. */
    public static RestTemplate trustEverythingRestTemplate() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] {TRUST_EVERYTHING}, new SecureRandom());

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod)
                    throws java.io.IOException {
                if (connection instanceof HttpsURLConnection https) {
                    https.setSSLSocketFactory(context.getSocketFactory());
                    https.setHostnameVerifier(ACCEPT_ANY_HOSTNAME);
                }
                super.prepareConnection(connection, httpMethod);
            }
        };
        factory.setConnectTimeout(3_000);
        factory.setReadTimeout(5_000);
        return new RestTemplate(factory);
    }
}
