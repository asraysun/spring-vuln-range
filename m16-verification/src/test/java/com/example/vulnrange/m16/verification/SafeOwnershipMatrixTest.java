package com.example.vulnrange.m16.verification;

import java.security.Principal;

import com.example.vulnrange.m16.access.EspdDocumentStore;
import com.example.vulnrange.m16.safe.SafeDocumentController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The negative authorization matrix: one row per caller type, asserted per protected endpoint.
 *
 * <p>Why this belongs in the pipeline: a functional test proves the owner can read their document. It
 * says nothing about the four other callers. When someone "just adds a new endpoint" and forgets the
 * ownership check, this matrix is what turns that into a red build instead of a pentest finding —
 * which is why checklist section 2 asks for it as a test, not as a review comment.
 *
 * <p>Copy this shape into your own project: enumerate {@code (endpoint, caller, object-ownership,
 * expected status)} and generate the cases, so a new endpoint without coverage is visible as a gap.
 */
class SafeOwnershipMatrixTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new SafeDocumentController(new EspdDocumentStore())).build();
    }

    private static Principal as(String name) {
        return () -> name;
    }

    @Test
    @DisplayName("owner reads own document")
    void ownerCanRead() throws Exception {
        mockMvc.perform(get("/safe16/documents/DOC-0001").principal(as("alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.owner").value("alice"));
    }

    @Test
    @DisplayName("another user gets 404, not the document and not its existence")
    void otherUserCannotRead() throws Exception {
        mockMvc.perform(get("/safe16/documents/DOC-0001").principal(as("bob")))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("caller from a different tenant cannot read either")
    void otherTenantCannotRead() throws Exception {
        mockMvc.perform(get("/safe16/documents/DOC-0002").principal(as("alice")))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("missing row and foreign row are indistinguishable")
    void missingAndForeignAreTheSame() throws Exception {
        mockMvc.perform(get("/safe16/documents/DOC-9999").principal(as("bob")))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("policy is stated where tests can assert on it")
    void policyIsMachineReadable() throws Exception {
        mockMvc.perform(get("/safe16/policy").principal(as("alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ownershipRule").isNotEmpty());
    }
}
