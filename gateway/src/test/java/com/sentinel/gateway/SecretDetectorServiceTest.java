package com.sentinel.gateway;

import com.sentinel.gateway.service.SecretDetectorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecretDetectorServiceTest {

    private SecretDetectorService secretDetectorService;

    @BeforeEach
    void setUp() {
        secretDetectorService = new SecretDetectorService();
    }

    @Test
    @DisplayName("Should detect live AWS Access Key and flag as CRITICAL")
    void testAwsKeyDetection() {
        String payload = "{\"prompt\": \"Please analyze this config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\"}";
        SecretDetectorService.DetectionResult result = secretDetectorService.inspectBody(payload);

        assertTrue(result.isCriticalFound());
        assertTrue(result.getDetectedPatterns().contains("AWS_ACCESS_KEY"));
        assertNotNull(result.getBlockReason());
    }

    @Test
    @DisplayName("Should detect PEM Private Key block and flag as CRITICAL")
    void testPemKeyDetection() {
        String payload = "{\"key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3\\n-----END PRIVATE KEY-----\"}";
        SecretDetectorService.DetectionResult result = secretDetectorService.inspectBody(payload);

        assertTrue(result.isCriticalFound());
        assertTrue(result.getDetectedPatterns().contains("PEM_PRIVATE_KEY"));
    }

    @Test
    @DisplayName("Should redact password JSON field in place while preserving structure")
    void testPasswordRedaction() {
        String payload = "{\"username\": \"admin\", \"password\": \"SuperSecretPass123!\"}";
        SecretDetectorService.DetectionResult result = secretDetectorService.inspectBody(payload);

        assertFalse(result.isCriticalFound());
        assertTrue(result.isRedactionOccurred());
        assertTrue(result.getSanitizedBody().contains("[REDACTED_PASSWORD]"));
        assertFalse(result.getSanitizedBody().contains("SuperSecretPass123!"));
    }

    @Test
    @DisplayName("Should redact Authorization Bearer token")
    void testBearerTokenRedaction() {
        String payload = "{\"headers\": {\"Authorization\": \"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"}}";
        SecretDetectorService.DetectionResult result = secretDetectorService.inspectBody(payload);

        assertTrue(result.isRedactionOccurred());
        assertTrue(result.getSanitizedBody().contains("[REDACTED_BEARER_TOKEN]"));
    }

    @Test
    @DisplayName("Should pass clean prompt without modification")
    void testCleanPrompt() {
        String payload = "{\"prompt\": \"Explain how Java Virtual Threads work in Spring Boot 3.2\"}";
        SecretDetectorService.DetectionResult result = secretDetectorService.inspectBody(payload);

        assertFalse(result.isCriticalFound());
        assertFalse(result.isRedactionOccurred());
        assertEquals(payload, result.getSanitizedBody());
    }

    @Test
    @DisplayName("Should extract and redact ChatGPT messages[].content.parts[] while preserving create_time and protocol metadata")
    void testChatGptProtocolIntegrityAndPartsRedaction() {
        String chatGptJson = "{\n" +
                "  \"action\": \"next\",\n" +
                "  \"messages\": [\n" +
                "    {\n" +
                "      \"id\": \"aaa272b5-1111-2222-3333-444455556666\",\n" +
                "      \"author\": { \"role\": \"user\" },\n" +
                "      \"create_time\": 1769304382.503,\n" +
                "      \"content\": {\n" +
                "        \"content_type\": \"text\",\n" +
                "        \"parts\": [\n" +
                "          \"Here is my client phone +1-555-0199 and email test@company.com\"\n" +
                "        ]\n" +
                "      },\n" +
                "      \"metadata\": {}\n" +
                "    }\n" +
                "  ],\n" +
                "  \"conversation_id\": \"conv-12345\",\n" +
                "  \"parent_message_id\": \"msg-67890\",\n" +
                "  \"model\": \"gpt-4o\"\n" +
                "}";

        SecretDetectorService.DetectionResult result = secretDetectorService.inspectBody(chatGptJson);

        assertTrue(result.isRedactionOccurred());
        String sanitized = result.getSanitizedBody();

        // 1. Verify create_time is 100% preserved and NOT corrupted into [REDACTED_PHONE_NUMBER].503
        assertTrue(sanitized.contains("1769304382.503"), "create_time numeric timestamp must be intact");
        assertFalse(sanitized.contains("[REDACTED_PHONE_NUMBER].503"), "create_time must never be matched as phone number");

        // 2. Verify protocol metadata is strictly preserved
        assertTrue(sanitized.contains("\"conversation_id\":\"conv-12345\"") || sanitized.contains("\"conversation_id\": \"conv-12345\""));
        assertTrue(sanitized.contains("\"parent_message_id\":\"msg-67890\"") || sanitized.contains("\"parent_message_id\": \"msg-67890\""));
        assertTrue(sanitized.contains("\"model\":\"gpt-4o\"") || sanitized.contains("\"model\": \"gpt-4o\""));

        // 3. Verify user content inside parts[] was accurately redacted
        assertTrue(sanitized.contains("[REDACTED_PHONE_NUMBER]"));
        assertTrue(sanitized.contains("[REDACTED_EMAIL]"));
        assertFalse(sanitized.contains("test@company.com"));

        // 4. Verify output is strictly valid parseable JSON
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        assertDoesNotThrow(() -> mapper.readTree(sanitized), "Sanitized output must be valid parseable JSON");
    }
}

