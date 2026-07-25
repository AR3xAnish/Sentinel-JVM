package com.sentinel.gateway.service;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SecretDetectorService {

    // Critical Secrets (Immediate BLOCK)
    private static final Pattern AWS_KEY_PATTERN = Pattern.compile("(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}");
    private static final Pattern PEM_PRIVATE_KEY_PATTERN = Pattern.compile("-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)?\\s?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA|EC|DSA|OPENSSH|PGP)?\\s?PRIVATE KEY-----");
    private static final Pattern GCP_SERVICE_ACCOUNT_PATTERN = Pattern.compile("\"type\"\\s*:\\s*\"service_account\"[\\s\\S]*?\"private_key\"");

    // Redactable Patterns
    private static final Pattern PASSWORD_JSON_PATTERN = Pattern.compile("(\"(?:password|passwd|pass|secret|client_secret)\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE);
    private static final Pattern BEARER_TOKEN_PATTERN = Pattern.compile("(Bearer\\s+)([A-Za-z0-9\\-\\._~\\+\\/]+=*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern API_KEY_FIELD_PATTERN = Pattern.compile("(\"(?:api_key|apiKey|access_token|auth_token|token)\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE);
    private static final Pattern GENERIC_API_KEY_KV_PATTERN = Pattern.compile("((?:api_key|apikey|secret_key|access_token)=)([A-Za-z0-9_\\-]{16,})", Pattern.CASE_INSENSITIVE);
    private static final Pattern JWT_PATTERN = Pattern.compile("eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*");
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b");

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DetectionResult {
        private boolean criticalFound;
        private String blockReason;
        private boolean redactionOccurred;
        private String sanitizedBody;
        private List<String> detectedPatterns;
    }

    public DetectionResult inspectBody(String body) {
        if (body == null || body.isBlank()) {
            return DetectionResult.builder()
                    .criticalFound(false)
                    .redactionOccurred(false)
                    .sanitizedBody(body)
                    .detectedPatterns(new ArrayList<>())
                    .build();
        }

        List<String> patterns = new ArrayList<>();

        // 1. Check CRITICAL secrets first
        if (AWS_KEY_PATTERN.matcher(body).find()) {
            patterns.add("AWS_ACCESS_KEY");
            return DetectionResult.builder()
                    .criticalFound(true)
                    .blockReason("Live AWS Cloud credentials (AKIA-prefixed key) detected in payload")
                    .sanitizedBody(body)
                    .detectedPatterns(patterns)
                    .build();
        }

        if (PEM_PRIVATE_KEY_PATTERN.matcher(body).find()) {
            patterns.add("PEM_PRIVATE_KEY");
            return DetectionResult.builder()
                    .criticalFound(true)
                    .blockReason("PEM Private Key block detected in payload")
                    .sanitizedBody(body)
                    .detectedPatterns(patterns)
                    .build();
        }

        if (GCP_SERVICE_ACCOUNT_PATTERN.matcher(body).find()) {
            patterns.add("GCP_SERVICE_ACCOUNT");
            return DetectionResult.builder()
                    .criticalFound(true)
                    .blockReason("GCP Service Account private key JSON detected in payload")
                    .sanitizedBody(body)
                    .detectedPatterns(patterns)
                    .build();
        }

        // 2. Check REDACTABLE secrets and mask in place
        String currentBody = body;
        boolean redacted = false;

        // Passwords in JSON
        Matcher passMatcher = PASSWORD_JSON_PATTERN.matcher(currentBody);
        if (passMatcher.find()) {
            patterns.add("PASSWORD_FIELD");
            currentBody = passMatcher.replaceAll("$1[REDACTED_PASSWORD]$3");
            redacted = true;
        }

        // Bearer tokens
        Matcher bearerMatcher = BEARER_TOKEN_PATTERN.matcher(currentBody);
        if (bearerMatcher.find()) {
            patterns.add("BEARER_TOKEN");
            currentBody = bearerMatcher.replaceAll("$1[REDACTED_BEARER_TOKEN]");
            redacted = true;
        }

        // API Key JSON fields
        Matcher apiKeyMatcher = API_KEY_FIELD_PATTERN.matcher(currentBody);
        if (apiKeyMatcher.find()) {
            patterns.add("API_KEY_JSON");
            currentBody = apiKeyMatcher.replaceAll("$1[REDACTED_API_KEY]$3");
            redacted = true;
        }

        // Generic Key-Value API Keys
        Matcher kvApiKeyMatcher = GENERIC_API_KEY_KV_PATTERN.matcher(currentBody);
        if (kvApiKeyMatcher.find()) {
            patterns.add("API_KEY_QUERY");
            currentBody = kvApiKeyMatcher.replaceAll("$1[REDACTED_API_KEY]");
            redacted = true;
        }

        // JWT tokens
        Matcher jwtMatcher = JWT_PATTERN.matcher(currentBody);
        if (jwtMatcher.find()) {
            patterns.add("JWT_TOKEN");
            currentBody = jwtMatcher.replaceAll("[REDACTED_JWT_TOKEN]");
            redacted = true;
        }

        // Credit Cards with Luhn Check verification
        Matcher ccMatcher = CREDIT_CARD_PATTERN.matcher(currentBody);
        StringBuffer sb = new StringBuffer();
        boolean foundCC = false;
        while (ccMatcher.find()) {
            String candidate = ccMatcher.group();
            if (isLuhnValid(candidate)) {
                ccMatcher.appendReplacement(sb, "[REDACTED_CREDIT_CARD]");
                foundCC = true;
            } else {
                ccMatcher.appendReplacement(sb, Matcher.quoteReplacement(candidate));
            }
        }
        ccMatcher.appendTail(sb);

        if (foundCC) {
            patterns.add("CREDIT_CARD_NUMBER");
            currentBody = sb.toString();
            redacted = true;
        }

        return DetectionResult.builder()
                .criticalFound(false)
                .redactionOccurred(redacted)
                .sanitizedBody(currentBody)
                .detectedPatterns(patterns)
                .build();
    }

    private boolean isLuhnValid(String number) {
        String cleaned = number.replaceAll("\\D", "");
        if (cleaned.length() < 13 || cleaned.length() > 19) return false;
        int sum = 0;
        boolean alternate = false;
        for (int i = cleaned.length() - 1; i >= 0; i--) {
            int n = Integer.parseInt(cleaned.substring(i, i + 1));
            if (alternate) {
                n *= 2;
                if (n > 9) {
                    n = (n % 10) + 1;
                }
            }
            sum += n;
            alternate = !alternate;
        }
        return (sum % 10 == 0);
    }
}
