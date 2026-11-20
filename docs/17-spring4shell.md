# Checklist 17 — Spring4Shell (CVE-2022-22965)

## Overview

Spring4Shell is a critical Remote Code Execution (RCE) vulnerability in Spring Framework that affects applications using Spring MVC with Java data binding.

**CVE-2022-22965** allows an attacker to execute arbitrary code on the server by sending malicious HTTP request parameters that exploit Spring's DataBinder component.

## Affected Versions

- Spring Framework 5.3.0 – 5.3.17
- Spring Framework 6.0.0 – 6.0.2
- Spring Boot 2.4.x – 2.4.13
- Spring Boot 2.5.x – 2.5.12
- Spring Boot 2.6.x – 2.6.6
- Spring Boot 3.0.0 – 3.0.1

## Vulnerable Pattern

The vulnerability occurs when Spring's DataBinder binds user-supplied request parameters to a model object without restricting which properties can be bound:

```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    // No disallowed fields!
}

@PostMapping("/profile")
public Map<String, Object> submitProfile(@ModelAttribute UserProfile profile) {
    // DataBinder binds ALL request parameters
}
```

## Exploit Chain

1. Attacker sends `class.module.classLoader` parameter
2. Spring resolves `class` to `java.lang.Class`
3. `module` → `Class.getModule()`
4. `classLoader` → `Module.getClassLoader()`
5. Attacker accesses ClassLoader to load arbitrary classes
6. Attacker executes arbitrary code via `Runtime.getRuntime().exec()`

## Mitigations

1. **Upgrade** to Spring Framework 5.3.18+ or 6.0.3+
2. **@InitBinder** with `setDisallowedFields("class.*")`
3. **Whitelist** allowed fields with `setAllowedFields()`
4. **@Valid** with validation annotations
5. **Disable SpEL** in data binding

## Safe Pattern

```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setDisallowedFields("class.*");
}
```

## Attack Script

Run: `bash attacks/17-spring4shell.sh`

## References

- [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965)
- [Spring Security Advisory](https://spring.io/security/cve-2022-22965)
- [OWASP Spring4Shell](https://owasp.org/www-community/vulnerabilities/Spring4Shell)
