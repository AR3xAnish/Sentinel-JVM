package com.sentinel.gateway.service;

import com.sentinel.gateway.model.ContentAnalysisResult;
import com.sentinel.gateway.model.DetectionCategory;
import com.sentinel.gateway.model.FindingDetail;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
public class SecretDetectorService {

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
    private static final Pattern PHONE_PATTERN = Pattern.compile("(?:\\+|\\b)(?:\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3,4}(?:[-.\\s]?\\d{4})?\\b");
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

        Set<DetectionCategory> categories = new HashSet<>();
        List<FindingDetail> findings = new ArrayList<>();
        Set<String> secretTypes = new HashSet<>();
        String currentBody = body;

        int piiCount = 0;
        int financialCount = 0;
        double sourceCodeScore = 0.0;
        double confidentialScore = 0.0;
        double hrScore = 0.0;
        double legalScore = 0.0;

        // --- 1. CREDENTIALS AND SECRETS ---
        Matcher awsMatcher = AWS_KEY_PATTERN.matcher(currentBody);
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
            currentBody = awsMatcher.replaceAll("[REDACTED_AWS_KEY]");
        }

        Matcher pemMatcher = PEM_PRIVATE_KEY_PATTERN.matcher(currentBody);
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
            currentBody = pemMatcher.replaceAll("[REDACTED_PRIVATE_KEY]");
        }

        Matcher gcpMatcher = GCP_SERVICE_ACCOUNT_PATTERN.matcher(currentBody);
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
            currentBody = gcpMatcher.replaceAll("[REDACTED_GCP_KEY]");
        }

        Matcher passMatcher = PASSWORD_JSON_PATTERN.matcher(currentBody);
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
            currentBody = passMatcher.replaceAll("$1[REDACTED_PASSWORD]$3");
        }

        Matcher bearerMatcher = BEARER_TOKEN_PATTERN.matcher(currentBody);
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
            currentBody = bearerMatcher.replaceAll("$1[REDACTED_BEARER_TOKEN]");
        }

        Matcher apiKeyMatcher = API_KEY_FIELD_PATTERN.matcher(currentBody);
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
            currentBody = apiKeyMatcher.replaceAll("$1[REDACTED_API_KEY]$3");
        }

        Matcher jwtMatcher = JWT_PATTERN.matcher(currentBody);
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
            currentBody = jwtMatcher.replaceAll("[REDACTED_JWT_TOKEN]");
        }

        Matcher dbMatcher = DB_CONN_STRING_PATTERN.matcher(currentBody);
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
            currentBody = dbMatcher.replaceAll("[REDACTED_DB_CONNECTION_STRING]");
        }

        // --- 2. FINANCIAL DATA (Run BEFORE PII) ---
        Matcher ccMatcher = CREDIT_CARD_PATTERN.matcher(currentBody);
        StringBuffer ccSb = new StringBuffer();
        int ccCount = 0;
        while (ccMatcher.find()) {
            String candidate = ccMatcher.group();
            if (isLuhnValid(candidate)) {
                ccMatcher.appendReplacement(ccSb, "[REDACTED_CREDIT_CARD]");
                ccCount++;
            } else {
                ccMatcher.appendReplacement(ccSb, Matcher.quoteReplacement(candidate));
            }
        }
        ccMatcher.appendTail(ccSb);

        if (ccCount > 0) {
            categories.add(DetectionCategory.FINANCIAL_DATA);
            financialCount += ccCount;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.FINANCIAL_DATA)
                    .findingType("CREDIT_CARD")
                    .maskedSnippet("****-****-****-****")
                    .confidence(1.0)
                    .count(ccCount)
                    .build());
            currentBody = ccSb.toString();
        }

        Matcher ibanMatcher = IBAN_BANK_PATTERN.matcher(currentBody);
        if (ibanMatcher.find()) {
            categories.add(DetectionCategory.FINANCIAL_DATA);
            financialCount++;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.FINANCIAL_DATA)
                    .findingType("BANK_ACCOUNT_IBAN")
                    .maskedSnippet("IBAN-****")
                    .confidence(0.90)
                    .count(1)
                    .build());
            currentBody = ibanMatcher.replaceAll("[REDACTED_BANK_ACCOUNT]");
        }

        Matcher salaryMatcher = SALARY_PAYROLL_PATTERN.matcher(currentBody);
        if (salaryMatcher.find()) {
            categories.add(DetectionCategory.FINANCIAL_DATA);
            financialCount++;
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.FINANCIAL_DATA)
                    .findingType("SALARY_PAYROLL")
                    .maskedSnippet("salary=***")
                    .confidence(0.85)
                    .count(1)
                    .build());
            currentBody = salaryMatcher.replaceAll("[REDACTED_SALARY_DATA]");
        }

        // --- 3. PERSONAL DATA (PII) ---
        Matcher emailMatcher = EMAIL_PATTERN.matcher(currentBody);
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
            currentBody = EMAIL_PATTERN.matcher(currentBody).replaceAll("[REDACTED_EMAIL]");
        }

        Matcher phoneMatcher = PHONE_PATTERN.matcher(currentBody);
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
            currentBody = PHONE_PATTERN.matcher(currentBody).replaceAll("[REDACTED_PHONE_NUMBER]");
        }

        Matcher ssnMatcher = SSN_GOVT_ID_PATTERN.matcher(currentBody);
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
            currentBody = SSN_GOVT_ID_PATTERN.matcher(currentBody).replaceAll("[REDACTED_GOVT_ID]");
        }

        Matcher empMatcher = EMP_CUST_ID_PATTERN.matcher(currentBody);
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
            currentBody = EMP_CUST_ID_PATTERN.matcher(currentBody).replaceAll("[REDACTED_EMPLOYEE_ID]");
        }

        // --- 4. SOURCE CODE DETECTION ---
        int javaMatches = countMatches(JAVA_CODE_PATTERN, body);
        int pythonMatches = countMatches(PYTHON_CODE_PATTERN, body);
        int jsMatches = countMatches(JS_TS_CODE_PATTERN, body);
        int sqlMatches = countMatches(SQL_CODE_PATTERN, body);

        int totalCodeMatches = javaMatches + pythonMatches + jsMatches + sqlMatches;
        int lineCount = body.split("\r\n|\r|\n").length;

        if (totalCodeMatches >= 2 || (totalCodeMatches >= 1 && lineCount > 4)) {
            sourceCodeScore = Math.min(1.0, 0.50 + (totalCodeMatches * 0.15));
            categories.add(DetectionCategory.SOURCE_CODE);
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.SOURCE_CODE)
                    .findingType("PROPRIETARY_SOURCE_CODE")
                    .maskedSnippet("[SOURCE_CODE_BLOCK]")
                    .confidence(sourceCodeScore)
                    .count(totalCodeMatches)
                    .build());
        }

        // --- 5. BUSINESS CONFIDENTIAL ---
        if (CONFIDENTIAL_DOC_PATTERN.matcher(body).find()) {
            confidentialScore = 0.90;
            categories.add(DetectionCategory.BUSINESS_CONFIDENTIAL);
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.BUSINESS_CONFIDENTIAL)
                    .findingType("BUSINESS_CONFIDENTIAL_MARKER")
                    .maskedSnippet("[CONFIDENTIAL_DOCUMENT]")
                    .confidence(0.90)
                    .count(1)
                    .build());
        }

        // --- 6. HR DATA ---
        if (HR_DOC_PATTERN.matcher(body).find()) {
            hrScore = 0.85;
            categories.add(DetectionCategory.HR_DATA);
            findings.add(FindingDetail.builder()
                    .category(DetectionCategory.HR_DATA)
                    .findingType("HR_EMPLOYEE_RECORD")
                    .maskedSnippet("[HR_RECORD]")
                    .confidence(0.85)
                    .count(1)
                    .build());
        }

        // --- 7. LEGAL DATA ---
        if (LEGAL_DOC_PATTERN.matcher(body).find()) {
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

        return ContentAnalysisResult.builder()
                .rawBody(body)
                .sanitizedBody(currentBody)
                .destinationHost(host)
                .detectedCategories(categories)
                .findings(findings)
                .secretTypes(secretTypes)
                .piiCount(piiCount)
                .financialDataIndicators(financialCount)
                .sourceCodeConfidence(sourceCodeScore)
                .businessConfidentialConfidence(confidentialScore)
                .hrDataIndicators(hrScore)
                .legalDataIndicators(legalScore)
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
