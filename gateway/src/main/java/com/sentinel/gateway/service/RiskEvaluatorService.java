package com.sentinel.gateway.service;

import com.sentinel.gateway.model.Action;
import com.sentinel.gateway.model.RiskTier;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RiskEvaluatorService {

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EvaluationResult {
        private RiskTier riskTier;
        private Action action;
        private Double compositeRiskScore;
        private String reason;
    }

    public EvaluationResult evaluateRisk(
            SecretDetectorService.DetectionResult secretResult,
            Double anomalyScore) {

        double effectiveAnomalyScore = (anomalyScore != null) ? anomalyScore : 0.05;
        List<String> patterns = secretResult.getDetectedPatterns();

        // 1. Critical secret match -> CRITICAL & BLOCK
        if (secretResult.isCriticalFound()) {
            return EvaluationResult.builder()
                    .riskTier(RiskTier.CRITICAL)
                    .action(Action.BLOCK)
                    .compositeRiskScore(1.00)
                    .reason(secretResult.getBlockReason())
                    .build();
        }

        // 2. High ML Anomaly combined with Redactable secrets -> CRITICAL & BLOCK
        if (secretResult.isRedactionOccurred() && effectiveAnomalyScore > 0.75) {
            return EvaluationResult.builder()
                    .riskTier(RiskTier.CRITICAL)
                    .action(Action.BLOCK)
                    .compositeRiskScore(Math.min(1.00, 0.70 + effectiveAnomalyScore * 0.3))
                    .reason("High behavioral anomaly (" + String.format("%.2f", effectiveAnomalyScore) + ") combined with sensitive data fields")
                    .build();
        }

        // Extreme standalone anomaly -> CRITICAL & BLOCK
        if (effectiveAnomalyScore >= 0.88) {
            return EvaluationResult.builder()
                    .riskTier(RiskTier.CRITICAL)
                    .action(Action.BLOCK)
                    .compositeRiskScore(effectiveAnomalyScore)
                    .reason("Critical behavioral anomaly score: " + String.format("%.2f", effectiveAnomalyScore))
                    .build();
        }

        // 3. Redactable secret found -> HIGH & REDACT
        if (secretResult.isRedactionOccurred()) {
            double score = Math.max(0.65, 0.50 + (effectiveAnomalyScore * 0.4));
            return EvaluationResult.builder()
                    .riskTier(RiskTier.HIGH)
                    .action(Action.REDACT)
                    .compositeRiskScore(score)
                    .reason("Sensitive pattern(s) detected and masked: " + String.join(", ", patterns))
                    .build();
        }

        // 4. Elevated behavioral anomaly without secrets -> HIGH
        if (effectiveAnomalyScore >= 0.70) {
            return EvaluationResult.builder()
                    .riskTier(RiskTier.HIGH)
                    .action(Action.REDACT) // Sanitize payload / flag
                    .compositeRiskScore(effectiveAnomalyScore)
                    .reason("Elevated behavioral anomaly score: " + String.format("%.2f", effectiveAnomalyScore))
                    .build();
        }

        // 5. Moderate anomaly -> MEDIUM & ALLOW
        if (effectiveAnomalyScore >= 0.40) {
            return EvaluationResult.builder()
                    .riskTier(RiskTier.MEDIUM)
                    .action(Action.ALLOW)
                    .compositeRiskScore(effectiveAnomalyScore)
                    .reason("Moderate anomaly detected")
                    .build();
        }

        // 6. Clean -> LOW & ALLOW
        return EvaluationResult.builder()
                .riskTier(RiskTier.LOW)
                .action(Action.ALLOW)
                .compositeRiskScore(Math.max(0.05, effectiveAnomalyScore))
                .reason("Traffic verified clean")
                .build();
    }
}
