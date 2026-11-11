package com.example.vulnrange.m16.verification;

import java.security.Principal;

import com.example.vulnrange.m16.access.EspdDocumentStore;
import com.example.vulnrange.m16.vuln.VulnerableDocumentController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The counter-test that makes the matrix above meaningful.
 *
 * <p>It asserts the <em>insecure</em> behaviour of {@code /vuln16}: a caller who is authenticated but
 * does not own the document still receives it. If your test suite contains a case like this and it
 * still passes, the suite is describing the bug rather than catching it — which is exactly what
 * happens when a project has "authorization tests" that only exercise the happy path.
 *
 * <p>Two ways to use this file:
 * <ol>
 *   <li>as documentation of what the vulnerable shape looks like in a test report;</li>
 *   <li>as a template for a CI gate: run the same matrix against a staging deployment of a real
 *       service and <strong>fail the build</strong> on any 2xx for a non-owner.</li>
 * </ol>
 */
class VulnerableEndpointRegressionTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new VulnerableDocumentController(new EspdDocumentStore())).build();
    }

    @Test
    @DisplayName("vulnerable endpoint leaks another user's document (this is the finding)")
    void crossUserReadIsAccepted() throws Exception {
        mockMvc.perform(get("/vuln16/documents/DOC-0001").principal(() -> "mallory"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("even without any principal at all the vulnerable endpoint answers")
    void anonymousReadIsAccepted() throws Exception {
        mockMvc.perform(get("/vuln16/documents/DOC-0001"))
                .andExpect(status().isOk());
    }

    @SuppressWarnings("unused")
    private static Principal as(String name) {
        return () -> name;
    }
}
