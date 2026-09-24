package com.sentinel.gateway.service;

import com.sentinel.gateway.model.Action;
import com.sentinel.gateway.model.DetectionCategory;
import com.sentinel.gateway.model.OrganizationPolicy;
import com.sentinel.gateway.model.PolicyRule;
import com.sentinel.gateway.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class PolicyService {

    private final PolicyRepository policyRepository;

    public Mono<OrganizationPolicy> getActivePolicy() {
        return policyRepository.findFirstByActiveTrue()
                .flatMap(p -> {
                    boolean modified = false;
                    List<String> approved = new ArrayList<>(p.getApprovedDestinations() != null ? p.getApprovedDestinations() : List.of());
                    for (String d : List.of("chatgpt.com", "openai.com", "api.openai.com")) {
                        if (!approved.contains(d)) {
                            approved.add(d);
                            modified = true;
                        }
                    }
                    if (p.getRestrictedDestinations() != null) {
                        List<String> restricted = new ArrayList<>(p.getRestrictedDestinations());
                        if (restricted.removeIf(d -> d.contains("chatgpt") || d.contains("openai"))) {
                            p.setRestrictedDestinations(restricted);
                            modified = true;
                        }
                    }
                    if (p.getUnapprovedDestinations() != null) {
                        List<String> unapproved = new ArrayList<>(p.getUnapprovedDestinations());
                        if (unapproved.removeIf(d -> d.contains("chatgpt") || d.contains("openai"))) {
                            p.setUnapprovedDestinations(unapproved);
                            modified = true;
                        }
                    }
                    if (modified) {
                        p.setApprovedDestinations(approved);
                        return policyRepository.save(p);
                    }
                    return Mono.just(p);
                })
                .onErrorResume(e -> {
                    log.warn("Failed to fetch active policy from Mongo: {}. Falling back to default enterprise policy.", e.getMessage());
                    return Mono.just(createDefaultPolicy());
                })
                .switchIfEmpty(Mono.defer(() -> {
                    log.info("No active policy found in Mongo. Seeding default policy.");
                    OrganizationPolicy defaultPolicy = createDefaultPolicy();
                    return policyRepository.save(defaultPolicy)
                            .onErrorReturn(defaultPolicy);
                }));
    }

    public Flux<OrganizationPolicy> getAllPolicies() {
        return policyRepository.findAll();
    }

    public Mono<OrganizationPolicy> saveAndValidatePolicy(OrganizationPolicy policy) {
        // Validate policy rules
        if (policy.getOrganizationName() == null || policy.getOrganizationName().isBlank()) {
            return Mono.error(new IllegalArgumentException("Organization name cannot be empty"));
        }
        if (policy.getRules() == null) {
            policy.setRules(Map.of());
        }

        return policyRepository.save(policy);
    }

    public Mono<OrganizationPolicy> activatePolicy(String policyId) {
        return policyRepository.findAll()
                .flatMap(p -> {
                    p.setActive(false);
                    return policyRepository.save(p);
                })
                .then(policyRepository.findById(policyId))
                .flatMap(p -> {
                    p.setActive(true);
                    return policyRepository.save(p);
                });
    }

    public OrganizationPolicy createDefaultPolicy() {
        return OrganizationPolicy.builder()
                .id("default_enterprise_policy")
                .organizationName("Sentinel Enterprise Corp")
                .version(1)
                .active(true)
                .approvedDestinations(List.of("chatgpt-enterprise", "internal-ai", "chatgpt.com", "openai.com", "api.openai.com"))
                .restrictedDestinations(List.of("huggingface.co"))
                .unapprovedDestinations(List.of("claude.ai", "api.anthropic.com", "api.perplexity.ai", "gemini.google.com"))
                .unapprovedDestinationAction(Action.BLOCK)
                .rules(Map.of(
                        DetectionCategory.CREDENTIALS_AND_SECRETS.name(), PolicyRule.builder()
                                .action(Action.BLOCK)
                                .description("Authentication secrets, cloud keys, and API tokens are prohibited.")
                                .threshold(0.5)
                                .build(),

                        DetectionCategory.PERSONAL_DATA.name(), PolicyRule.builder()
                                .action(Action.REDACT)
                                .description("Personally Identifiable Information (PII) must be masked in-flight.")
                                .threshold(0.5)
                                .build(),

                        DetectionCategory.FINANCIAL_DATA.name(), PolicyRule.builder()
                                .action(Action.BLOCK)
                                .description("Payment cards, bank accounts, and financial records are strictly prohibited.")
                                .threshold(0.5)
                                .build(),

                        DetectionCategory.SOURCE_CODE.name(), PolicyRule.builder()
                                .action(Action.BLOCK)
                                .description("Proprietary source code snippets exceeding safety threshold are prohibited.")
                                .threshold(0.6)
                                .build(),

                        DetectionCategory.BUSINESS_CONFIDENTIAL.name(), PolicyRule.builder()
                                .action(Action.BLOCK)
                                .description("Internal strategy, roadmap, and confidential business documents are prohibited.")
                                .threshold(0.6)
                                .build(),

                        DetectionCategory.HR_DATA.name(), PolicyRule.builder()
                                .action(Action.BLOCK)
                                .description("Employee records, performance reviews, and salary data are prohibited.")
                                .threshold(0.5)
                                .build(),

                        DetectionCategory.LEGAL_DATA.name(), PolicyRule.builder()
                                .action(Action.BLOCK)
                                .description("Contracts, NDAs, and legal documents are prohibited.")
                                .threshold(0.5)
                                .build()
                ))
                .build();
    }
}
