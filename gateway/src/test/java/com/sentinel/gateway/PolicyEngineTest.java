package com.sentinel.gateway;

import com.sentinel.gateway.model.*;
import com.sentinel.gateway.service.PolicyEngineService;
import com.sentinel.gateway.service.PolicyService;
import com.sentinel.gateway.service.SecretDetectorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class PolicyEngineTest {

    private SecretDetectorService secretDetectorService;
    private PolicyEngineService policyEngineService;
    private PolicyService policyService;

    @BeforeEach
    void setUp() {
        secretDetectorService = new SecretDetectorService();
        policyEngineService = new PolicyEngineService();
        policyService = Mockito.mock(PolicyService.class);
    }

    @Test
    @DisplayName("Test 1: Normal prompt -> ALLOW under normal policy")
    void testNormalPromptAllowed() {
        String prompt = "Explain binary search algorithm in Java 21.";
        ContentAnalysisResult result = secretDetectorService.analyzeContent(prompt, "chatgpt.com");
        OrganizationPolicy policy = createTestPolicy();

        PolicyDecision decision = policyEngineService.evaluate(result, policy);

        assertEquals(Action.ALLOW, decision.getAction());
        assertEquals(RiskTier.LOW, decision.getRiskTier());
        assertTrue(decision.getReason().contains("No sensitive organizational data detected"));
    }

    @Test
    @DisplayName("Test 2: Password JSON -> REDACT or BLOCK according to policy")
    void testPasswordHandled() {
        String prompt = "Debug this config: {\"dbPassword\": \"MySuperPass2026!\"}";
        ContentAnalysisResult result = secretDetectorService.analyzeContent(prompt, "api.openai.com");
        OrganizationPolicy policy = createTestPolicy();

        PolicyDecision decision = policyEngineService.evaluate(result, policy);

        assertEquals(Action.BLOCK, decision.getAction());
        assertTrue(result.getSanitizedBody().contains("[REDACTED_PASSWORD]"));
        assertEquals(DetectionCategory.CREDENTIALS_AND_SECRETS, decision.getMatchedCategory());
    }

    @Test
    @DisplayName("Test 3: PII (Email + Phone) -> REDACT according to policy")
    void testPiiRedacted() {
        String prompt = "Send user confirmation to john.doe@example.com or call +1-555-0199.";
        ContentAnalysisResult result = secretDetectorService.analyzeContent(prompt, "chatgpt.com");
        OrganizationPolicy policy = createTestPolicy();

        PolicyDecision decision = policyEngineService.evaluate(result, policy);

        assertEquals(Action.REDACT, decision.getAction());
        assertTrue(result.getSanitizedBody().contains("[REDACTED_EMAIL]"));
        assertTrue(result.getSanitizedBody().contains("[REDACTED_PHONE_NUMBER]"));
    }

    @Test
    @DisplayName("Test 4: Financial Data (Credit Card) -> BLOCK according to policy")
    void testFinancialDataBlocked() {
        // Valid Luhn test card number 4532015112830366
        String prompt = "Process payment for card 4532015112830366";
        ContentAnalysisResult result = secretDetectorService.analyzeContent(prompt, "claude.ai");
        OrganizationPolicy policy = createTestPolicy();

        PolicyDecision decision = policyEngineService.evaluate(result, policy);

        assertEquals(Action.BLOCK, decision.getAction());
        assertEquals(RiskTier.CRITICAL, decision.getRiskTier());
        assertEquals(DetectionCategory.FINANCIAL_DATA, decision.getMatchedCategory());
    }

    @Test
    @DisplayName("Test 5: Substantial Source Code -> BLOCK according to policy")
    void testSourceCodeBlocked() {
        String codePrompt = "public class SentinelEngine {\n" +
                "    private void process() {\n" +
                "        System.out.println(\"Running engine\");\n" +
                "    }\n" +
                "}";
        ContentAnalysisResult result = secretDetectorService.analyzeContent(codePrompt, "claude.ai");
        OrganizationPolicy policy = createTestPolicy();

        PolicyDecision decision = policyEngineService.evaluate(result, policy);

        assertEquals(Action.BLOCK, decision.getAction());
        assertEquals(DetectionCategory.SOURCE_CODE, decision.getMatchedCategory());
    }

    @Test
    @DisplayName("Test 6: AWS Key -> BLOCK")
    void testAwsKeyBlocked() {
        String prompt = "Deploy key: AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF";
        ContentAnalysisResult result = secretDetectorService.analyzeContent(prompt, "claude.ai");
        OrganizationPolicy policy = createTestPolicy();

        PolicyDecision decision = policyEngineService.evaluate(result, policy);

        assertEquals(Action.BLOCK, decision.getAction());
        assertEquals(RiskTier.CRITICAL, decision.getRiskTier());
    }

    @Test
    @DisplayName("Test 7: Private Key -> BLOCK")
    void testPrivateKeyBlocked() {
        String prompt = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----";
        ContentAnalysisResult result = secretDetectorService.analyzeContent(prompt, "chatgpt.com");
        OrganizationPolicy policy = createTestPolicy();

        PolicyDecision decision = policyEngineService.evaluate(result, policy);

        assertEquals(Action.BLOCK, decision.getAction());
    }

    @Test
    @DisplayName("Test 8: POLICY SWITCHING TEST - Same PII request gives REDACT under Policy A, but BLOCK under Policy B")
    void testPolicySwitchingDynamically() {
        String piiPrompt = "Contact customer at alice@company.org or phone +1-555-0188";

        // Policy A: personalData = REDACT
        OrganizationPolicy policyA = createTestPolicy();

        // Policy B: personalData = BLOCK
        OrganizationPolicy policyB = createTestPolicy();
        policyB.setCategoryRule(DetectionCategory.PERSONAL_DATA, PolicyRule.builder()
                .action(Action.BLOCK)
                .description("All PII is strictly prohibited.")
                .threshold(0.5)
                .build());

        ContentAnalysisResult analysis = secretDetectorService.analyzeContent(piiPrompt, "chatgpt.com");

        // Evaluate Policy A
        PolicyDecision decisionA = policyEngineService.evaluate(analysis, policyA);
        assertEquals(Action.REDACT, decisionA.getAction(), "Policy A should REDACT PII");

        // Evaluate Policy B (without recompiling/restarting app)
        PolicyDecision decisionB = policyEngineService.evaluate(analysis, policyB);
        assertEquals(Action.BLOCK, decisionB.getAction(), "Policy B should BLOCK PII on exact same input");
    }

    private OrganizationPolicy createTestPolicy() {
        OrganizationPolicy policy = OrganizationPolicy.builder()
                .id("policy_test")
                .organizationName("Test Organization")
                .version(1)
                .active(true)
                .approvedDestinations(List.of("chatgpt-enterprise"))
                .restrictedDestinations(List.of("chatgpt.com", "api.openai.com"))
                .unapprovedDestinations(List.of("claude.ai", "api.anthropic.com"))
                .rules(new HashMap<>())
                .build();

        policy.setCategoryRule(DetectionCategory.CREDENTIALS_AND_SECRETS, PolicyRule.builder().action(Action.BLOCK).build());
        policy.setCategoryRule(DetectionCategory.PERSONAL_DATA, PolicyRule.builder().action(Action.REDACT).build());
        policy.setCategoryRule(DetectionCategory.FINANCIAL_DATA, PolicyRule.builder().action(Action.BLOCK).build());
        policy.setCategoryRule(DetectionCategory.SOURCE_CODE, PolicyRule.builder().action(Action.BLOCK).threshold(0.5).build());
        policy.setCategoryRule(DetectionCategory.BUSINESS_CONFIDENTIAL, PolicyRule.builder().action(Action.BLOCK).build());
        policy.setCategoryRule(DetectionCategory.HR_DATA, PolicyRule.builder().action(Action.BLOCK).build());
        policy.setCategoryRule(DetectionCategory.LEGAL_DATA, PolicyRule.builder().action(Action.BLOCK).build());

        return policy;
    }
}
