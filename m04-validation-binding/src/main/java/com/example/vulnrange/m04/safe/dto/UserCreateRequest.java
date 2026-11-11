package com.example.vulnrange.m04.safe.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * The request contract, deliberately narrower than anything the persistence layer can store.
 *
 * <p>Points that matter for review:
 * <ul>
 *   <li>there is no {@code role}, {@code enabled}, {@code monthlyLimit} or {@code priceOverride} to
 *       assign — the field that cannot be set cannot be escalated (contrast with
 *       {@code LegacyUserEntity});</li>
 *   <li>{@code @JsonIgnoreProperties(ignoreUnknown = false)} makes unknown fields an error instead of
 *       a silent no-op, so a client sending {@code role} is visible in logs and rejected;</li>
 *   <li>every field has a bound: length, format and character class.</li>
 * </ul>
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public class UserCreateRequest {

    @NotBlank
    @Size(min = 3, max = 32)
    @Pattern(regexp = "^[a-z0-9._-]+$", message = "lowercase letters, digits, dot, underscore, dash only")
    private String username;

    @NotBlank
    @Email
    @Size(max = 254)
    private String email;

    @Size(max = 20)
    @Pattern(regexp = "^T-\\d{3}$", message = "tenant id must look like T-100")
    private String tenantId;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }
}
