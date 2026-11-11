package com.example.vulnrange.m16;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Checklist section 16 — can your tooling actually see what is in front of it?
 *
 * <p>Two mechanisms:
 * <ul>
 *   <li>{@link com.example.vulnrange.m16.vuln.FlaggableSastFixtures} — a small set of textbook
 *       insecure patterns used as a negative test for SAST (SpotBugs+FindSecBugs, Semgrep, Sonar);</li>
 *   <li>{@code src/test/java} — a negative authorization matrix that must PASS on {@code /safe16} and
 *       would FAIL if the same rules were missing, which is what makes the pattern worth copying into
 *       your own project.</li>
 * </ul>
 */
@SpringBootApplication
public class M16VerificationApplication {

    public static void main(String[] args) {
        System.out.println("""
                ===================================================================
                 m16-verification — verification fixtures, EDUCATIONAL ONLY
                 Tests:  ./mvnw -pl m16-verification test
                 SAST:   ./mvnw -Psast -pl m16-verification verify
                ===================================================================""");
        SpringApplication.run(M16VerificationApplication.class, args);
    }
}
