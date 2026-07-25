package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InspectionResponse {
    private Action decision;
    private RiskTier riskTier;
    private Double riskScore;
    private String redactedBody;
    private List<String> detectedPatterns;
    private String blockReason;
    private Long executionTimeMs;
    private String logId;
}
