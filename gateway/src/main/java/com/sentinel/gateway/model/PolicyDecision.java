package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PolicyDecision {

    private Action action; // ALLOW, REDACT, BLOCK
    private RiskTier riskTier; // LOW, MEDIUM, HIGH, CRITICAL
    private String reason;
    private DetectionCategory matchedCategory;
    private PolicyRule matchedRule;
    private String destinationStatus; // APPROVED, RESTRICTED, UNAPPROVED
}
