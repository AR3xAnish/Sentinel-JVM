package com.sentinel.gateway.service;

import com.sentinel.gateway.model.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Set;

@Slf4j
@Service
public class PolicyEngineService {

    public PolicyDecision evaluate(ContentAnalysisResult analysisResult, OrganizationPolicy policy) {
        String host = analysisResult.getDestinationHost() != null ? analysisResult.getDestinationHost().toLowerCase() : "unknown";
        String destStatus = determineDestinationStatus(host, policy);

        Set<DetectionCategory> categories = analysisResult.getDetectedCategories();

        if (categories == null || categories.isEmpty()) {
            // No sensitive categories detected
            if ("UNAPPROVED".equals(destStatus) && policy.getUnapprovedDestinationAction() == Action.BLOCK) {
                return PolicyDecision.builder()
                        .action(Action.BLOCK)
                        .riskTier(RiskTier.MEDIUM)
                        .reason(String.format("Destination service '%s' is UNAPPROVED under policy '%s'.", host, policy.getOrganizationName()))
                        .destinationStatus(destStatus)
                        .build();
            }

            return PolicyDecision.builder()
                    .action(Action.ALLOW)
                    .riskTier(RiskTier.LOW)
                    .reason(String.format("No sensitive organizational data detected. Query allowed for %s.", host))
                    .destinationStatus(destStatus)
                    .build();
        }

        Action highestAction = Action.ALLOW;
        RiskTier highestRisk = RiskTier.LOW;
        DetectionCategory matchedCategory = null;
        PolicyRule matchedRule = null;
        String decisionReason = null;

        for (DetectionCategory category : categories) {
            PolicyRule rule = policy.getCategoryRule(category);
            if (rule == null) {
                continue;
            }

            // Check confidence threshold if applicable
            if (!meetsConfidenceThreshold(category, analysisResult, rule.getThreshold())) {
                continue;
            }

            Action categoryAction = rule.getAction();

            // Check destination override if specified
            if (rule.getDestinationOverrides() != null && rule.getDestinationOverrides().containsKey(host)) {
                categoryAction = rule.getDestinationOverrides().get(host);
            }

            // Evaluate precedence: BLOCK > REDACT > ALLOW
            if (categoryAction == Action.BLOCK) {
                highestAction = Action.BLOCK;
                highestRisk = calculateRiskTier(category, Action.BLOCK);
                matchedCategory = category;
                matchedRule = rule;
                decisionReason = String.format("%s prohibited from submission to %s under policy rule %s (%s).",
                        formatCategoryName(category), host, category.name(), policy.getOrganizationName());
                break; // Highest action reached
            } else if (categoryAction == Action.REDACT && highestAction != Action.BLOCK) {
                highestAction = Action.REDACT;
                highestRisk = calculateRiskTier(category, Action.REDACT);
                matchedCategory = category;
                matchedRule = rule;
                decisionReason = String.format("%s detected and masked in-flight for %s under policy rule %s.",
                        formatCategoryName(category), host, category.name());
            }
        }

        if (decisionReason == null) {
            decisionReason = String.format("Request passed policy checks for organization '%s'.", policy.getOrganizationName());
        }

        return PolicyDecision.builder()
                .action(highestAction)
                .riskTier(highestRisk)
                .reason(decisionReason)
                .matchedCategory(matchedCategory)
                .matchedRule(matchedRule)
                .destinationStatus(destStatus)
                .build();
    }

    private String determineDestinationStatus(String host, OrganizationPolicy policy) {
        if (policy.getApprovedDestinations() != null && policy.getApprovedDestinations().stream().anyMatch(host::contains)) {
            return "APPROVED";
        }
        if (policy.getRestrictedDestinations() != null && policy.getRestrictedDestinations().stream().anyMatch(host::contains)) {
            return "RESTRICTED";
        }
        if (policy.getUnapprovedDestinations() != null && policy.getUnapprovedDestinations().stream().anyMatch(host::contains)) {
            return "UNAPPROVED";
        }
        return "UNAPPROVED";
    }

    private boolean meetsConfidenceThreshold(DetectionCategory category, ContentAnalysisResult result, double threshold) {
        switch (category) {
            case SOURCE_CODE:
                return result.getSourceCodeConfidence() >= threshold;
            case BUSINESS_CONFIDENTIAL:
                return result.getBusinessConfidentialConfidence() >= threshold;
            case HR_DATA:
                return result.getHrDataIndicators() >= threshold;
            case LEGAL_DATA:
                return result.getLegalDataIndicators() >= threshold;
            default:
                return true;
        }
    }

    private RiskTier calculateRiskTier(DetectionCategory category, Action action) {
        if (action == Action.BLOCK) {
            if (category == DetectionCategory.CREDENTIALS_AND_SECRETS || category == DetectionCategory.CREDENTIAL || category == DetectionCategory.FINANCIAL_DATA) {
                return RiskTier.CRITICAL;
            }
            return RiskTier.HIGH;
        } else if (action == Action.REDACT) {
            return RiskTier.HIGH;
        }
        return RiskTier.MEDIUM;
    }

    private String formatCategoryName(DetectionCategory category) {
        switch (category) {
            case CREDENTIALS_AND_SECRETS:
            case CREDENTIAL:
                return "Authentication secrets and API keys";
            case PERSONAL_DATA: return "Personal Identifiable Information (PII)";
            case FINANCIAL_DATA: return "Financial and payment data";
            case SOURCE_CODE: return "Proprietary source code";
            case BUSINESS_CONFIDENTIAL: return "Confidential business intelligence";
            case HR_DATA: return "Human Resources employee records";
            case LEGAL_DATA: return "Legal contracts and documentation";
            default: return category.name();
        }
    }
}
