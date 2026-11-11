package com.example.vulnrange.m02.config;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Access-control configuration for the range.
 *
 * <p>The {@code /vuln2/**} rules reproduce the mistakes from checklist section 2: leftover
 * {@code permitAll}, a whole-path bypass through {@link WebSecurityCustomizer#ignoring()}, and a
 * "reads are public" matcher that also covers a state-changing GET. The {@code /safe2/**} block is
 * the reference: explicit allows plus a default-deny tail.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // CSRF is demonstrated in m07-web-layer; disabled here so PoC scripts stay readable.
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // VULNERABLE (intentional): leftovers that survive a hundred reviews.
                        .requestMatchers("/vuln2/admin/**").permitAll()
                        .requestMatchers("/vuln2/internal/**").permitAll()
                        .requestMatchers("/vuln2/register").permitAll()
                        // "Only reads are public" — and someone routed a state change through GET.
                        .requestMatchers(HttpMethod.GET, "/vuln2/subscriptions/*/cancel").permitAll()
//                        .requestMatchers("/vuln2/**").authenticated()
                        .requestMatchers("/safe2/admin/**").hasRole("ADMIN")
                        .requestMatchers("/safe2/**").authenticated()
                        // Reference default: deny everything that is not enumerated above.
//                        .anyRequest().denyAll())
                )
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    /**
     * VULNERABLE (intentional): {@code ignoring()} takes the request out of the filter chain
     * completely — authentication, CSRF protection and security headers all disappear, silently.
     * Prefer authenticated matchers; if an endpoint must be public, say so with {@code permitAll()}
     * so it stays visible to reviewers and scanners.
     */
    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers("/vuln2/bypass/**");
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    InMemoryUserDetailsManager users(PasswordEncoder encoder) {
        // VULNERABLE (intentional): "mallory" obtained ROLE_ADMIN through self-service registration
        // (see POST /vuln2/register), which is exactly how role checks get subverted in practice.
        List<UserDetails> seed = List.of(
                User.builder().username("alice").password(encoder.encode("alice-pass"))
                        .authorities("USER").build(),
                User.builder().username("bob").password(encoder.encode("bob-pass"))
                        .authorities("USER").build(),
                User.builder().username("mallory").password(encoder.encode("mallory-pass"))
                        .authorities("USER", "ROLE_ADMIN").build(),
                User.builder().username("svc-report").password(encoder.encode("svc-pass"))
                        .authorities("SCOPE_report:read").build());
        return new InMemoryUserDetailsManager(seed);
    }

    /** username -&gt; tenant id. A real service reads this from the token claim, never a request param. */
    @Bean
    Map<String, String> tenantDirectory() {
        Map<String, String> directory = new ConcurrentHashMap<>();
        directory.put("alice", "T-100");
        directory.put("bob", "T-200");
        directory.put("mallory", "T-300");
        directory.put("svc-report", "T-100");
        return directory;
    }
}
