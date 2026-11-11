package com.example.vulnrange.m12.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Two configurations selected by profile, so the same jar can be started in the "as shipped"
 * (vulnerable) and in the hardened shape.
 */
@Configuration
@EnableWebSecurity
public class ActuatorChainConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    InMemoryUserDetailsManager users(PasswordEncoder encoder) {
        UserDetails operator = User.builder().username("operator")
                .password(encoder.encode("operator-pass")).roles("ACTUATOR").build();
        return new InMemoryUserDetailsManager(operator);
    }

    /** Default profile: every request is permitted, including all actuator endpoints. */
    @Bean
    @Profile("!safe")
    SecurityFilterChain exposedChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .build();
    }

    /** Safe profile: health/info for monitoring, everything else authenticated; management port is separate. */
    @Bean
    @Profile("safe")
    SecurityFilterChain hardenedChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        .requestMatchers("/actuator/**").hasRole("ACTUATOR")
                        .requestMatchers("/api/**").permitAll()
                        .anyRequest().denyAll())
                .httpBasic(Customizer.withDefaults())
                // CSRF stays on for everything that is not a monitoring GET.
                .build();
    }
}
