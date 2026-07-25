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
}
