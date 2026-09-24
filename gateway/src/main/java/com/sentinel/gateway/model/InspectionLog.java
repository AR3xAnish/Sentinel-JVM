package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "inspection_logs")
public class InspectionLog {
    @Id
    private String id;
    private Instant timestamp;
    private String destinationHost;
    private String destinationStatus; // APPROVED, RESTRICTED, UNAPPROVED
    private String requestPath;
    private String method;
    private String clientIp;
    private String userId;

    private Action decision; // ALLOW, REDACT, BLOCK
    private RiskTier riskTier; // LOW, MEDIUM, HIGH, CRITICAL
    private Double riskScore;
    
    @Builder.Default
    private Set<String> detectedCategories = new HashSet<>();
    private String matchedCategory;
    private List<FindingDetail> findings;
    private List<String> detectedPatterns;
    private String blockReason;
    private String policyReason;

    private Integer originalPayloadSize;
    private Integer redactedPayloadSize;
    
    // Privacy-Preserving Logging: Only safe/sanitized body stored in audit log
    private String safeBody;
    private String redactedBody;

    private Long executionTimeMs;
    private Double anomalyScore;
}
