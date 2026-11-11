package com.example.vulnrange.m07.config;

import java.util.List;
import java.util.function.Supplier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Two filter chains, so the same application can show both the broken and the hardened web layer.
 *
 * <p>Chain A ({@code /vuln7/**}) reproduces the classic browser-side mistakes:
 * CSRF switched off for a cookie-authenticated state change, {@code headers().disable()}, and a CORS
 * source that pairs wildcard origin patterns with credentials.
 *
 * <p>Chain B ({@code /safe7/**}) is the reference: CSRF with a double-submit cookie that a SPA can
 * actually use, an explicit CORS allow-list, and the full header set including a restrictive CSP.
 */
@Configuration
@EnableWebSecurity
public class WebLayerSecurityConfig {

    /** Chain A - vulnerable. */
    @Bean
    @org.springframework.core.annotation.Order(1)
    public SecurityFilterChain vulnerableChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/vuln7/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                // VULNERABLE: the state-changing endpoints below rely on a session cookie, and CSRF
                // protection is switched off globally "because the mobile app broke".
                .csrf(csrf -> csrf.disable())
                // VULNERABLE: no X-Content-Type-Options, no X-Frame-Options/CSP, no HSTS, no referrer policy.
                .headers(headers -> headers.disable())
                .cors(cors -> cors.configurationSource(vulnerableCorsSource()))
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    /** Chain B - hardened. */
    @Bean
    @org.springframework.core.annotation.Order(2)
    public SecurityFilterChain safeChain(HttpSecurity http) throws Exception {
        CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        // Prod: sameSite("Strict"|"Lax") + secure(true). Local PoC keeps secure=false over http.
        tokenRepository.setCookieCustomizer(cookie -> cookie.sameSite("Lax").path("/"));

        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        // The default XorCsrfTokenRequestAttributeHandler adds BREACH mitigation and expects the
        // XOR-encoded value; the plain handler keeps token == cookie value, which is what a
        // curl-based PoC (and many HTTP clients) sends. Browser-only clients can keep the default.

        return http
                .securityMatcher("/safe7/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(tokenRepository)
                        .csrfTokenRequestHandler(requestHandler)
                        // Enforced on POST/PUT/PATCH/DELETE; safe methods stay untouched.
                        .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/safe7/**", "POST")))
                // Forces the token to be materialised into the cookie on every request, including
                // GETs - a well-known Spring Security 6.x SPA gotcha.
                .addFilterAfter(new CsrfCookieFilter(), org.springframework.security.web.csrf.CsrfFilter.class)
                .cors(cors -> cors.configurationSource(safeCorsSource()))
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"))
                        .frameOptions(frame -> frame.deny())
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000))
                        .referrerPolicy(referrer -> referrer.policy(
                                org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
                                        .ReferrerPolicy.NO_REFERRER)))
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    /** Default for anything else in this module. */
    @Bean
    @org.springframework.core.annotation.Order(3)
    public SecurityFilterChain defaultChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth.anyRequest().denyAll())
                .build();
    }

    /** VULNERABLE: wildcard origin patterns combined with credentialed requests. */
    @Bean
    public CorsConfigurationSource vulnerableCorsSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowCredentials(true);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("Authorization"));
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /** Reference: explicit origins, minimal methods/headers, credentials only where it is intended. */
    @Bean
    public CorsConfigurationSource safeCorsSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:4200"));
        config.setAllowCredentials(true);
        config.setAllowedMethods(List.of("GET", "POST"));
        config.setAllowedHeaders(List.of("X-XSRF-TOKEN", "Content-Type"));
        config.setMaxAge(600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/safe7/profile", config);
        return source;
    }

    /** Makes sure the CSRF cookie exists before the SPA needs it. */
    static class CsrfCookieFilter extends OncePerRequestFilter {
        @Override
        @SuppressWarnings("unchecked")
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                        FilterChain filterChain) throws ServletException, java.io.IOException {
            Object attribute = request.getAttribute(CsrfToken.class.getName());
            if (attribute instanceof Supplier<?> supplier) {
                ((Supplier<CsrfToken>) supplier).get();
            }
            filterChain.doFilter(request, response);
        }
    }
}
