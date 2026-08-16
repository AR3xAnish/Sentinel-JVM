package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.List;

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
    private String requestPath;
    private String method;
    private String clientIp;
    private String userId;
    private Action decision;
    private RiskTier riskTier;
    private Double riskScore;
    private List<String> detectedPatterns;
    private String blockReason;
    private Integer originalPayloadSize;
    private Integer redactedPayloadSize;
    private String body;
    private String redactedBody;
    private Long executionTimeMs;
    private Double anomalyScore;
}
