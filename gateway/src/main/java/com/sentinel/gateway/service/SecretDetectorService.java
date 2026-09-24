package com.sentinel.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.sentinel.gateway.model.ContentAnalysisResult;
import com.sentinel.gateway.model.DetectionCategory;
import com.sentinel.gateway.model.FindingDetail;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
public class SecretDetectorService {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    // 1. CREDENTIALS AND SECRETS PATTERNS
    private static final Pattern AWS_KEY_PATTERN = Pattern.compile("(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}");
    private static final Pattern PEM_PRIVATE_KEY_PATTERN = Pattern.compile("-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)?\\s?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA|EC|DSA|OPENSSH|PGP)?\\s?PRIVATE KEY-----");
    private static final Pattern GCP_SERVICE_ACCOUNT_PATTERN = Pattern.compile("\"type\"\\s*:\\s*\"service_account\"[\\s\\S]*?\"private_key\"");
    private static final Pattern PASSWORD_JSON_PATTERN = Pattern.compile("(\"(?:password|passwd|pass|secret|client_secret|dbPassword)\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE);
    private static final Pattern BEARER_TOKEN_PATTERN = Pattern.compile("(Bearer\\s+)([A-Za-z0-9\\-\\._~\\+\\/]+=*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern API_KEY_FIELD_PATTERN = Pattern.compile("(\"(?:api_key|apiKey|access_token|auth_token|token)\"\\s*:\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE);
    private static final Pattern GENERIC_API_KEY_KV_PATTERN = Pattern.compile("((?:api_key|apikey|secret_key|access_token)=)([A-Za-z0-9_\\-]{16,})", Pattern.CASE_INSENSITIVE);
    private static final Pattern JWT_PATTERN = Pattern.compile("eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*");
    private static final Pattern DB_CONN_STRING_PATTERN = Pattern.compile("(jdbc:(?:postgresql|mysql|oracle|sqlserver)|mongodb\\+srv)://[^\"]+", Pattern.CASE_INSENSITIVE);

    // 2. PERSONAL DATA (PII) PATTERNS
    private static final Pattern EMAIL_PATTERN = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");
    // Formatted telephone pattern requiring delimiters or international '+' prefix to prevent false matching on timestamps
    private static final Pattern PHONE_PATTERN = Pattern.compile("(?:\\+\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]\\d{3,4}(?:[-.\\s]\\d{4})?\\b|\\+\\d{1,3}[-.\\s]?\\d{6,14}\\b");
    private static final Pattern SSN_GOVT_ID_PATTERN = Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b");
    private static final Pattern EMP_CUST_ID_PATTERN = Pattern.compile("\\b(?:EMP|CUST|USR|CUSTOMER|EMP_ID)-\\d{4,8}\\b", Pattern.CASE_INSENSITIVE);

    // 3. FINANCIAL DATA PATTERNS
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b");
    private static final Pattern IBAN_BANK_PATTERN = Pattern.compile("\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b");
    private static final Pattern SALARY_PAYROLL_PATTERN = Pattern.compile("(?:salary|payroll|compensation|annual bonus|w2 earnings)\\s*[:=]\\s*\\$?\\d+(?:,\\d{3})*(?:\\.\\d{2})?", Pattern.CASE_INSENSITIVE);

    // 4. SOURCE CODE PATTERNS
    private static final Pattern JAVA_CODE_PATTERN = Pattern.compile("(?:public\\s+class|private\\s+void|import\\s+java\\.|@Override|System\\.out\\.println)", Pattern.MULTILINE);
    private static final Pattern PYTHON_CODE_PATTERN = Pattern.compile("(?:def\\s+[a-zA-Z_][a-zA-Z0-9_]*\\s*\\(|import\\s+[a-zA-Z0-9_]+|class\\s+[a-zA-Z0-9_]+\\s*:)", Pattern.MULTILINE);
    private static final Pattern JS_TS_CODE_PATTERN = Pattern.compile("(?:function\\s+[a-zA-Z0-9_]+\\s*\\(|const\\s+[a-zA-Z0-9_]+\\s*=|export\\s+default\\s+function)", Pattern.MULTILINE);
    private static final Pattern SQL_CODE_PATTERN = Pattern.compile("\\b(?:SELECT\\s+.+?\\s+FROM|INSERT\\s+INTO|UPDATE\\s+.+?\\s+SET|DELETE\\s+FROM|CREATE\\s+TABLE|DROP\\s+TABLE)\\b", Pattern.CASE_INSENSITIVE);

    // 5. BUSINESS CONFIDENTIAL PATTERNS
    private static final Pattern CONFIDENTIAL_DOC_PATTERN = Pattern.compile("\\b(?:CONFIDENTIAL|STRICTLY PRIVATE|INTERNAL ONLY|PROPRIETARY AND CONFIDENTIAL|UNRELEASED PRODUCT|M&A STRATEGY|ACQUISITION ROADMAP)\\b", Pattern.CASE_INSENSITIVE);

    // 6. HR DATA PATTERNS
    private static final Pattern HR_DOC_PATTERN = Pattern.compile("\\b(?:PERFORMANCE REVIEW|EMPLOYEE DISCIPLINARY|SALARY BAND|COMPENSATION MATRIX|CANDIDATE INTERVIEW FEEDBACK|TERMINATION NOTICE)\\b", Pattern.CASE_INSENSITIVE);

    // 7. LEGAL DATA PATTERNS
    private static final Pattern LEGAL_DOC_PATTERN = Pattern.compile("\\b(?:NON-DISCLOSURE AGREEMENT|MUTUAL NDA|ATTORNEY-CLIENT PRIVILEGED|MASTER SERVICES AGREEMENT|LITIGATION HOLD|SETTLEMENT AGREEMENT)\\b", Pattern.CASE_INSENSITIVE);

    // Protocol metadata fields that MUST NEVER be inspected or modified
    private static final Set<String> PROTOCOL_METADATA_FIELDS = Set.of(
            "create_time", "created_at", "created", "timestamp", "time", "date",
            "conversation_id", "parent_message_id", "id", "message_id", "req_id", "request_id",
            "model", "action", "role", "type", "author", "timezone_offset_min", "timezone",
            "history_and_training_disabled", "system_hints", "client_contextual_info",
            "serialization_metadata", "metadata", "status", "code", "index", "content_type"
    );

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

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TextDlpResult {
        private String sanitizedText;
        private boolean modified;
        @Builder.Default
        private Set<DetectionCategory> categories = new HashSet<>();
        @Builder.Default
        private List<FindingDetail> findings = new ArrayList<>();
        @Builder.Default
        private Set<String> secretTypes = new HashSet<>();
        private int piiCount;
        private int financialCount;
        private double sourceCodeScore;
        private double confidentialScore;
        private double hrScore;
        private double legalScore;
    }

    private static class TextDlpAccumulator {
        final Set<DetectionCategory> categories = new HashSet<>();
        final List<FindingDetail> findings = new ArrayList<>();
        final Set<String> secretTypes = new HashSet<>();
        int piiCount = 0;
        int financialCount = 0;
        double sourceCodeScore = 0.0;
        double confidentialScore = 0.0;
        double hrScore = 0.0;
        double legalScore = 0.0;

        void merge(TextDlpResult result) {
            if (result == null) return;
            if (result.getCategories() != null) categories.addAll(result.getCategories());
            if (result.getFindings() != null) findings.addAll(result.getFindings());
            if (result.getSecretTypes() != null) secretTypes.addAll(result.getSecretTypes());
            piiCount += result.getPiiCount();
            financialCount += result.getFinancialCount();
            sourceCodeScore = Math.max(sourceCodeScore, result.getSourceCodeScore());
            confidentialScore = Math.max(confidentialScore, result.getConfidentialScore());
            hrScore = Math.max(hrScore, result.getHrScore());
            legalScore = Math.max(legalScore, result.getLegalScore());
        }
    }

    public DetectionResult inspectBody(String body) {
        ContentAnalysisResult result = analyzeContent(body, "unknown");
        List<String> patterns = new ArrayList<>();
        if (result.getFindings() != null) {
            result.getFindings().forEach(f -> patterns.add(f.getFindingType()));
        }
        boolean critical = result.getSecretTypes().contains("AWS_ACCESS_KEY") || 
                           result.getSecretTypes().contains("PEM_PRIVATE_KEY") || 
                           result.getSecretTypes().contains("GCP_SERVICE_ACCOUNT");
        
        boolean redacted = !body.equals(result.getSanitizedBody());

        return DetectionResult.builder()
                .criticalFound(critical)
                .blockReason(critical ? "Critical security credential detected in payload" : null)
                .redactionOccurred(redacted)
                .sanitizedBody(result.getSanitizedBody())
                .detectedPatterns(patterns)
                .build();
    }

    public ContentAnalysisResult analyzeContent(String body, String host) {
        if (body == null || body.isBlank()) {
            return ContentAnalysisResult.builder()
                    .rawBody(body)
                    .sanitizedBody(body)
                    .destinationHost(host)
                    .detectedCategories(new HashSet<>())
                    .findings(new ArrayList<>())
                    .secretTypes(new HashSet<>())
                    .build();
        }

        String trimmed = body.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                JsonNode rootNode = OBJECT_MAPPER.readTree(body);
                if (rootNode != null && (rootNode.isObject() || rootNode.isArray())) {
                    return analyzeJsonPayload(rootNode, body, host);
                }
            } catch (Exception e) {
                log.debug("Payload is not valid JSON, analyzing as raw text: {}", e.getMessage());
            }
        }

        // Fallback for raw text payloads (e.g. unit test string prompts)
        TextDlpResult textResult = scanAndRedactText(body);
        return ContentAnalysisResult.builder()
                .rawBody(body)
                .sanitizedBody(textResult.getSanitizedText())
                .destinationHost(host)
                .detectedCategories(textResult.getCategories())
                .findings(textResult.getFindings())
                .secretTypes(textResult.getSecretTypes())
                .piiCount(textResult.getPiiCount())
                .financialDataIndicators(textResult.getFinancialCount())
                .sourceCodeConfidence(textResult.getSourceCodeScore())
                .businessConfidentialConfidence(textResult.getConfidentialScore())
                .hrDataIndicators(textResult.getHrScore())
                .legalDataIndicators(textResult.getLegalScore())
                .build();
    }

    private ContentAnalysisResult analyzeJsonPayload(JsonNode rootNode, String originalBody, String host) {
        AtomicBoolean modified = new AtomicBoolean(false);
        TextDlpAccumulator accumulator = new TextDlpAccumulator();
        boolean targetedExtractionFound = false;

        // 1. ChatGPT Web and OpenAI API: inspect messages[].content (and parts[])
        if (rootNode.has("messages") && rootNode.get("messages").isArray()) {
            ArrayNode messagesArray = (ArrayNode) rootNode.get("messages");
            for (JsonNode messageNode : messagesArray) {
                if (messageNode.isObject()) {
                    ObjectNode msgObj = (ObjectNode) messageNode;
                    if (msgObj.has("content")) {
                        JsonNode contentNode = msgObj.get("content");

                        // 1a. ChatGPT Web backend: content is an object with "parts" array of text strings
                        if (contentNode.isObject() && contentNode.has("parts") && contentNode.get("parts").isArray()) {
                            ArrayNode partsArray = (ArrayNode) contentNode.get("parts");
                            for (int i = 0; i < partsArray.size(); i++) {
                                JsonNode partNode = partsArray.get(i);
                                if (partNode.isTextual()) {
                                    targetedExtractionFound = true;
                                    String text = partNode.asText();
                                    TextDlpResult result = scanAndRedactText(text);
                                    accumulator.merge(result);
                                    if (result.isModified()) {
                                        partsArray.set(i, new TextNode(result.getSanitizedText()));
                                        modified.set(true);
                                    }
                                } else if (partNode.isObject() && partNode.has("text") && partNode.get("text").isTextual()) {
                                    targetedExtractionFound = true;
                                    String text = partNode.get("text").asText();
                                    TextDlpResult result = scanAndRedactText(text);
                                    accumulator.merge(result);
                                    if (result.isModified()) {
                                        ((ObjectNode) partNode).put("text", result.getSanitizedText());
                                        modified.set(true);
                                    }
                                }
                            }
                        }
                        // 1b. OpenAI / Claude API: content is a direct text string
                        else if (contentNode.isTextual()) {
                            targetedExtractionFound = true;
                            String text = contentNode.asText();
                            TextDlpResult result = scanAndRedactText(text);
                            accumulator.merge(result);
                            if (result.isModified()) {
                                msgObj.put("content", result.getSanitizedText());
                                modified.set(true);
                            }
                        }
                        // 1c. Multimodal parts array: content is an array of objects
                        else if (contentNode.isArray()) {
                            ArrayNode contentArray = (ArrayNode) contentNode;
                            for (int i = 0; i < contentArray.size(); i++) {
                                JsonNode itemNode = contentArray.get(i);
                                if (itemNode.isTextual()) {
                                    targetedExtractionFound = true;
                                    String text = itemNode.asText();
                                    TextDlpResult result = scanAndRedactText(text);
                                    accumulator.merge(result);
                                    if (result.isModified()) {
                                        contentArray.set(i, new TextNode(result.getSanitizedText()));
                                        modified.set(true);
                                    }
                                } else if (itemNode.isObject() && itemNode.has("text") && itemNode.get("text").isTextual()) {
                                    targetedExtractionFound = true;
                                    String text = itemNode.get("text").asText();
                                    TextDlpResult result = scanAndRedactText(text);
                                    accumulator.merge(result);
                                    if (result.isModified()) {
                                        ((ObjectNode) itemNode).put("text", result.getSanitizedText());
                                        modified.set(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Google Gemini API: inspect contents[].parts[].text
        if (rootNode.has("contents") && rootNode.get("contents").isArray()) {
            ArrayNode contentsArray = (ArrayNode) rootNode.get("contents");
            for (JsonNode contentItem : contentsArray) {
                if (contentItem.isObject() && contentItem.has("parts") && contentItem.get("parts").isArray()) {
                    ArrayNode partsArray = (ArrayNode) contentItem.get("parts");
                    for (int i = 0; i < partsArray.size(); i++) {
                        JsonNode partNode = partsArray.get(i);
                        if (partNode.isObject() && partNode.has("text") && partNode.get("text").isTextual()) {
                            targetedExtractionFound = true;
                            String text = partNode.get("text").asText();
                            TextDlpResult result = scanAndRedactText(text);
                            accumulator.merge(result);
                            if (result.isModified()) {
                                ((ObjectNode) partNode).put("text", result.getSanitizedText());
                                modified.set(true);
                            }
                        } else if (partNode.isTextual()) {
                            targetedExtractionFound = true;
                            String text = partNode.asText();
                            TextDlpResult result = scanAndRedactText(text);
                            accumulator.merge(result);
                            if (result.isModified()) {
                                partsArray.set(i, new TextNode(result.getSanitizedText()));
                                modified.set(true);
                            }
                        }
                    }
                }
            }
        }

        // 3. Top-level prompt/query fields
        if (rootNode.isObject()) {
            ObjectNode objNode = (ObjectNode) rootNode;
            String[] promptFields = {"prompt", "query", "input", "message", "text"};
            for (String field : promptFields) {
                if (objNode.has(field) && objNode.get(field).isTextual()) {
                    targetedExtractionFound = true;
                    String text = objNode.get(field).asText();
                    TextDlpResult result = scanAndRedactText(text);
                    accumulator.merge(result);
                    if (result.isModified()) {
                        objNode.put(field, result.getSanitizedText());
                        modified.set(true);
                    }
                }
            }
        }

        // 4. Safe fallback for arbitrary JSON structures (e.g. config payloads)
        if (!targetedExtractionFound) {
            inspectGenericJsonValues(rootNode, accumulator, modified);
        }

        // 5. Serialize sanitized JSON and validate integrity
        String sanitizedBody = originalBody;
        boolean isValidJson = true;
        if (modified.get()) {
            try {
                sanitizedBody = OBJECT_MAPPER.writeValueAsString(rootNode);
                // Strict validation: verify that output parses as valid JSON
                OBJECT_MAPPER.readTree(sanitizedBody);
            } catch (Exception e) {
                log.error("CRITICAL: Failed to validate sanitized JSON! Falling back to original body to prevent downstream failure.", e);
                sanitizedBody = originalBody;
                isValidJson = false;
            }
        }

        // 6. Defensive logging in dev mode (NEVER log secrets, credentials, or full payload bodies)
        log.info("DLP Inspection Complete for destination '{}' | Modified: {} | Valid JSON: {} | Detections: {} | Categories: {}",
                host,
                modified.get(),
                isValidJson,
                accumulator.findings.size(),
                accumulator.categories.stream().map(DetectionCategory::name).toList());

        return ContentAnalysisResult.builder()
                .rawBody(originalBody)
                .sanitizedBody(sanitizedBody)
                .destinationHost(host)
                .detectedCategories(accumulator.categories)
                .findings(accumulator.findings)
                .secretTypes(accumulator.secretTypes)
                .piiCount(accumulator.piiCount)
                .financialDataIndicators(accumulator.financialCount)
                .sourceCodeConfidence(accumulator.sourceCodeScore)
                .businessConfidentialConfidence(accumulator.confidentialScore)
                .hrDataIndicators(accumulator.hrScore)
                .legalDataIndicators(accumulator.legalScore)
                .build();
    }

    private void inspectGenericJsonValues(JsonNode node, TextDlpAccumulator accumulator, AtomicBoolean modified) {
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = obj.fields();
            List<String> keysToUpdate = new ArrayList<>();
            Map<String, String> updates = new HashMap<>();

            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey().toLowerCase();
                JsonNode child = entry.getValue();

                // Strictly skip protocol metadata fields, numeric fields, booleans, and nulls
                if (PROTOCOL_METADATA_FIELDS.contains(key) || child.isNumber() || child.isBoolean() || child.isNull()) {
                    continue;
                }

                if (child.isTextual()) {
                    String text = child.asText();
                    if (isSecretFieldKey(key)) {
                        accumulator.categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
                        accumulator.secretTypes.add("PASSWORD");
                        accumulator.findings.add(FindingDetail.builder()
                                .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                                .findingType("PASSWORD")
                                .maskedSnippet("password=***")
                                .confidence(0.95)
                                .count(1)
                                .build());
                        updates.put(entry.getKey(), "[REDACTED_PASSWORD]");
                        keysToUpdate.add(entry.getKey());
                    } else {
                        TextDlpResult result = scanAndRedactText(text);
                        accumulator.merge(result);
                        if (result.isModified()) {
                            updates.put(entry.getKey(), result.getSanitizedText());
                            keysToUpdate.add(entry.getKey());
                        }
                    }
                } else if (child.isObject() || child.isArray()) {
                    inspectGenericJsonValues(child, accumulator, modified);
                }
            }

            for (String k : keysToUpdate) {
                obj.put(k, updates.get(k));
                modified.set(true);
            }
        } else if (node.isArray()) {
            ArrayNode arr = (ArrayNode) node;
            for (int i = 0; i < arr.size(); i++) {
                JsonNode child = arr.get(i);
                if (child.isTextual()) {
                    String text = child.asText();
                    TextDlpResult result = scanAndRedactText(text);
                    accumulator.merge(result);
                    if (result.isModified()) {
                        arr.set(i, new TextNode(result.getSanitizedText()));
                        modified.set(true);
                    }
                } else if (child.isObject() || child.isArray()) {
                    inspectGenericJsonValues(child, accumulator, modified);
                }
            }
        }
    }

    private boolean isSecretFieldKey(String key) {
        String lower = key.toLowerCase();
        return lower.equals("password") || lower.equals("passwd") || lower.equals("pass")
                || lower.equals("secret") || lower.equals("client_secret") || lower.equals("dbpassword");
    }

    public TextDlpResult scanAndRedactText(String text) {
        if (text == null || text.isBlank()) {
            return TextDlpResult.builder()
                    .sanitizedText(text)
                    .modified(false)
                    .categories(new HashSet<>())
                    .findings(new ArrayList<>())
                    .secretTypes(new HashSet<>())
                    .build();
        }

        Set<DetectionCategory> categories = new HashSet<>();
        List<FindingDetail> findings = new ArrayList<>();
        Set<String> secretTypes = new HashSet<>();
        String currentText = text;

        int piiCount = 0;
        int financialCount = 0;
        double sourceCodeScore = 0.0;
        double confidentialScore = 0.0;
        double hrScore = 0.0;
        double legalScore = 0.0;

        // --- 1. CREDENTIALS AND SECRETS ---
        Matcher awsMatcher = AWS_KEY_PATTERN.matcher(currentText);
        if (awsMatcher.find()) {
            categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
            secretTypes.add("AWS_ACCESS_KEY");
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                    .findingType("AWS_ACCESS_KEY")
                    .maskedSnippet("AKIA***")
                    .confidence(1.0)
                    .count(1)
                    .build());
            currentText = awsMatcher.replaceAll("[REDACTED_AWS_KEY]");
        }

        Matcher pemMatcher = PEM_PRIVATE_KEY_PATTERN.matcher(currentText);
        if (pemMatcher.find()) {
            categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
            secretTypes.add("PEM_PRIVATE_KEY");
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                    .findingType("PEM_PRIVATE_KEY")
                    .maskedSnippet("-----BEGIN PRIVATE KEY-----")
                    .confidence(1.0)
                    .count(1)
                    .build());
            currentText = pemMatcher.replaceAll("[REDACTED_PRIVATE_KEY]");
        }

        Matcher gcpMatcher = GCP_SERVICE_ACCOUNT_PATTERN.matcher(currentText);
        if (gcpMatcher.find()) {
            categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
            secretTypes.add("GCP_SERVICE_ACCOUNT");
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                    .findingType("GCP_SERVICE_ACCOUNT")
                    .maskedSnippet("gcp-service-account-key")
                    .confidence(1.0)
                    .count(1)
                    .build());
            currentText = gcpMatcher.replaceAll("[REDACTED_GCP_KEY]");
        }

        Matcher passMatcher = PASSWORD_JSON_PATTERN.matcher(currentText);
        if (passMatcher.find()) {
            categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
            secretTypes.add("PASSWORD");
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                    .findingType("PASSWORD")
                    .maskedSnippet("password=***")
                    .confidence(0.95)
                    .count(1)
                    .build());
            currentText = passMatcher.replaceAll("$1[REDACTED_PASSWORD]$3");
        }

        Matcher bearerMatcher = BEARER_TOKEN_PATTERN.matcher(currentText);
        if (bearerMatcher.find()) {
            categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
            secretTypes.add("BEARER_TOKEN");
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                    .findingType("BEARER_TOKEN")
                    .maskedSnippet("Bearer ***")
                    .confidence(0.95)
                    .count(1)
                    .build());
            currentText = bearerMatcher.replaceAll("$1[REDACTED_BEARER_TOKEN]");
        }

        Matcher apiKeyMatcher = API_KEY_FIELD_PATTERN.matcher(currentText);
        if (apiKeyMatcher.find()) {
            categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
            secretTypes.add("API_KEY");
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                    .findingType("API_KEY")
                    .maskedSnippet("api_key=***")
                    .confidence(0.90)
                    .count(1)
                    .build());
            currentText = apiKeyMatcher.replaceAll("$1[REDACTED_API_KEY]$3");
        }

        Matcher genericKeyMatcher = GENERIC_API_KEY_KV_PATTERN.matcher(currentText);
        if (genericKeyMatcher.find()) {
            categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
            secretTypes.add("GENERIC_API_KEY");
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                    .findingType("GENERIC_API_KEY")
                    .maskedSnippet("api_key=***")
                    .confidence(0.85)
                    .count(1)
                    .build());
            currentText = genericKeyMatcher.replaceAll("$1[REDACTED_API_KEY]");
        }

        Matcher jwtMatcher = JWT_PATTERN.matcher(currentText);
        if (jwtMatcher.find()) {
            categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
            secretTypes.add("JWT_TOKEN");
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                    .findingType("JWT_TOKEN")
                    .maskedSnippet("eyJ***")
                    .confidence(0.95)
                    .count(1)
                    .build());
            currentText = jwtMatcher.replaceAll("[REDACTED_JWT_TOKEN]");
        }

        Matcher dbMatcher = DB_CONN_STRING_PATTERN.matcher(currentText);
        if (dbMatcher.find()) {
            categories.add(DetectionCategory.CREDENTIALS_AND_SECRETS);
            secretTypes.add("DB_CREDENTIALS");
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.CREDENTIALS_AND_SECRETS)
                    .findingType("DB_CREDENTIALS")
                    .maskedSnippet("jdbc:***")
                    .confidence(0.95)
                    .count(1)
                    .build());
            currentText = dbMatcher.replaceAll("[REDACTED_DB_CONNECTION_STRING]");
        }

        // --- 2. FINANCIAL DATA (Run BEFORE PII) ---
        Matcher ccMatcher = CREDIT_CARD_PATTERN.matcher(currentText);
        StringBuffer ccSb = new StringBuffer();
        int ccCount = 0;
        while (ccMatcher.find()) {
            String match = ccMatcher.group();
            if (isLuhnValid(match)) {
                ccCount++;
                ccMatcher.appendReplacement(ccSb, "[REDACTED_CREDIT_CARD]");
            } else {
                ccMatcher.appendReplacement(ccSb, Matcher.quoteReplacement(match));
            }
        }
        ccMatcher.appendTail(ccSb);
        currentText = ccSb.toString();
        if (ccCount > 0) {
            categories.add(DetectionCategory.FINANCIAL_DATA);
            financialCount += ccCount;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.FINANCIAL_DATA)
                    .findingType("CREDIT_CARD_NUMBER")
                    .maskedSnippet("[REDACTED_CREDIT_CARD]")
                    .confidence(1.0)
                    .count(ccCount)
                    .build());
        }

        Matcher ibanMatcher = IBAN_BANK_PATTERN.matcher(currentText);
        if (ibanMatcher.find()) {
            categories.add(DetectionCategory.FINANCIAL_DATA);
            financialCount++;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.FINANCIAL_DATA)
                    .findingType("IBAN_BANK_ACCOUNT")
                    .maskedSnippet("[REDACTED_IBAN]")
                    .confidence(0.90)
                    .count(1)
                    .build());
            currentText = ibanMatcher.replaceAll("[REDACTED_IBAN]");
        }

        Matcher salaryMatcher = SALARY_PAYROLL_PATTERN.matcher(currentText);
        if (salaryMatcher.find()) {
            categories.add(DetectionCategory.FINANCIAL_DATA);
            financialCount++;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.FINANCIAL_DATA)
                    .findingType("COMPENSATION_SALARY")
                    .maskedSnippet("salary=[REDACTED]")
                    .confidence(0.85)
                    .count(1)
                    .build());
            currentText = salaryMatcher.replaceAll("salary=[REDACTED_FINANCIAL_RECORD]");
        }

        // --- 3. PERSONAL DATA (PII) ---
        Matcher emailMatcher = EMAIL_PATTERN.matcher(currentText);
        int emailCount = 0;
        while (emailMatcher.find()) {
            emailCount++;
        }
        if (emailCount > 0) {
            categories.add(DetectionCategory.PERSONAL_DATA);
            piiCount += emailCount;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.PERSONAL_DATA)
                    .findingType("EMAIL")
                    .maskedSnippet("[REDACTED_EMAIL]")
                    .confidence(0.95)
                    .count(emailCount)
                    .build());
            currentText = EMAIL_PATTERN.matcher(currentText).replaceAll("[REDACTED_EMAIL]");
        }

        Matcher phoneMatcher = PHONE_PATTERN.matcher(currentText);
        int phoneCount = 0;
        while (phoneMatcher.find()) {
            phoneCount++;
        }
        if (phoneCount > 0) {
            categories.add(DetectionCategory.PERSONAL_DATA);
            piiCount += phoneCount;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.PERSONAL_DATA)
                    .findingType("PHONE_NUMBER")
                    .maskedSnippet("[REDACTED_PHONE]")
                    .confidence(0.85)
                    .count(phoneCount)
                    .build());
            currentText = PHONE_PATTERN.matcher(currentText).replaceAll("[REDACTED_PHONE_NUMBER]");
        }

        Matcher ssnMatcher = SSN_GOVT_ID_PATTERN.matcher(currentText);
        if (ssnMatcher.find()) {
            categories.add(DetectionCategory.PERSONAL_DATA);
            piiCount++;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.PERSONAL_DATA)
                    .findingType("GOVT_ID_SSN")
                    .maskedSnippet("***-**-****")
                    .confidence(0.90)
                    .count(1)
                    .build());
            currentText = SSN_GOVT_ID_PATTERN.matcher(currentText).replaceAll("[REDACTED_GOVT_ID]");
        }

        Matcher empMatcher = EMP_CUST_ID_PATTERN.matcher(currentText);
        if (empMatcher.find()) {
            categories.add(DetectionCategory.PERSONAL_DATA);
            piiCount++;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.PERSONAL_DATA)
                    .findingType("EMPLOYEE_CUSTOMER_ID")
                    .maskedSnippet("EMP-****")
                    .confidence(0.85)
                    .count(1)
                    .build());
            currentText = EMP_CUST_ID_PATTERN.matcher(currentText).replaceAll("[REDACTED_EMPLOYEE_ID]");
        }

        // --- 4. SOURCE CODE DETECTION ---
        int javaMatches = countMatches(JAVA_CODE_PATTERN, text);
        int pythonMatches = countMatches(PYTHON_CODE_PATTERN, text);
        int jsMatches = countMatches(JS_TS_CODE_PATTERN, text);
        int sqlMatches = countMatches(SQL_CODE_PATTERN, text);

        if (javaMatches >= 2 || pythonMatches >= 2 || jsMatches >= 2 || sqlMatches >= 2) {
            sourceCodeScore = Math.min(1.0, 0.5 + (javaMatches + pythonMatches + jsMatches + sqlMatches) * 0.15);
            categories.add(DetectionCategory.SOURCE_CODE);
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.SOURCE_CODE)
                    .findingType("PROPRIETARY_SOURCE_CODE")
                    .maskedSnippet("[SOURCE_CODE_BLOCK]")
                    .confidence(sourceCodeScore)
                    .count(javaMatches + pythonMatches + jsMatches + sqlMatches)
                    .build());
        }

        // --- 5. BUSINESS CONFIDENTIAL ---
        if (CONFIDENTIAL_DOC_PATTERN.matcher(text).find()) {
            confidentialScore = 0.90;
            categories.add(DetectionCategory.BUSINESS_CONFIDENTIAL);
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.BUSINESS_CONFIDENTIAL)
                    .findingType("CONFIDENTIAL_MARKER")
                    .maskedSnippet("[CONFIDENTIAL_DOCUMENT]")
                    .confidence(0.90)
                    .count(1)
                    .build());
        }

        // --- 6. HR DATA ---
        if (HR_DOC_PATTERN.matcher(text).find()) {
            hrScore = 0.85;
            categories.add(DetectionCategory.HR_DATA);
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.HR_DATA)
                    .findingType("HR_EMPLOYEE_DATA")
                    .maskedSnippet("[HR_RECORD]")
                    .confidence(0.85)
                    .count(1)
                    .build());
        }

        // --- 7. LEGAL DATA ---
        if (LEGAL_DOC_PATTERN.matcher(text).find()) {
            legalScore = 0.85;
            categories.add(DetectionCategory.LEGAL_DATA);
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.LEGAL_DATA)
                    .findingType("LEGAL_CONTRACT_NDA")
                    .maskedSnippet("[LEGAL_DOC]")
                    .confidence(0.85)
                    .count(1)
                    .build());
        }

        boolean modified = !text.equals(currentText);

        return TextDlpResult.builder()
                .sanitizedText(currentText)
                .modified(modified)
                .categories(categories)
                .findings(findings)
                .secretTypes(secretTypes)
                .piiCount(piiCount)
                .financialCount(financialCount)
                .sourceCodeScore(sourceCodeScore)
                .confidentialScore(confidentialScore)
                .hrScore(hrScore)
                .legalScore(legalScore)
                .build();
    }

    private int countMatches(Pattern pattern, String text) {
        Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
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
