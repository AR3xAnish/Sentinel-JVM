package com.sentinel.gateway.controller;

import com.sentinel.gateway.model.Action;
import com.sentinel.gateway.model.InspectionLog;
import com.sentinel.gateway.model.InspectionRequest;
import com.sentinel.gateway.model.InspectionResponse;
import com.sentinel.gateway.model.PolicyDecision;
import com.sentinel.gateway.model.RiskTier;
import com.sentinel.gateway.repository.InspectionLogRepository;
import com.sentinel.gateway.service.AlertService;
import com.sentinel.gateway.service.ContentAnalysisService;
import com.sentinel.gateway.service.PolicyEngineService;
import com.sentinel.gateway.service.PolicyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Slf4j
@RestController
@RequestMapping("/api/inspect")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class InspectionController {

    private final ContentAnalysisService contentAnalysisService;
    private final PolicyService policyService;
    private final PolicyEngineService policyEngineService;
    private final InspectionLogRepository inspectionLogRepository;
    private final AlertService alertService;

    @PostMapping
    public Mono<ResponseEntity<InspectionResponse>> inspectPayload(@RequestBody InspectionRequest request) {
        long startTime = System.currentTimeMillis();

        String body = request.getBody() != null ? request.getBody() : "";
        String destinationHost = request.getDestinationHost() != null ? request.getDestinationHost() : "unknown";

        // 1. Analyze content (Deterministic detectors + ML helper)
        return contentAnalysisService.analyze(body, destinationHost)
                .flatMap(analysisResult -> 
                    // 2. Fetch active policy
                    policyService.getActivePolicy()
                        .flatMap(activePolicy -> {
                            // 3. Evaluate Policy Engine
                            PolicyDecision decision = policyEngineService.evaluate(analysisResult, activePolicy);
                            long executionTime = System.currentTimeMillis() - startTime;

                            List<String> patterns = new ArrayList<>();
                            if (analysisResult.getFindings() != null) {
                                analysisResult.getFindings().forEach(f -> patterns.add(f.getFindingType()));
                            }

                            Set<String> categoryNames = new HashSet<>();
                            if (analysisResult.getDetectedCategories() != null) {
                                analysisResult.getDetectedCategories().forEach(cat -> categoryNames.add(cat.name()));
                            }

                            // Privacy-Preserving Logging: do NOT log raw body containing unmasked secrets
                            String safeBodyLog = decision.getAction() == Action.REDACT ? 
                                    analysisResult.getSanitizedBody() : 
                                    (decision.getAction() == Action.BLOCK ? "[BLOCKED_PAYLOAD]" : body);

                            InspectionLog logEntry = InspectionLog.builder()
                                    .timestamp(Instant.now())
                                    .destinationHost(destinationHost)
                                    .destinationStatus(decision.getDestinationStatus())
                                    .requestPath(request.getRequestPath() != null ? request.getRequestPath() : "/")
                                    .method(request.getMethod() != null ? request.getMethod() : "POST")
                                    .clientIp(request.getClientIp() != null ? request.getClientIp() : "127.0.0.1")
                                    .userId(request.getUserId() != null ? request.getUserId() : "anonymous")
                                    .decision(decision.getAction())
                                    .riskTier(decision.getRiskTier())
                                    .riskScore(decision.getAction() == Action.BLOCK ? 0.95 : (decision.getAction() == Action.REDACT ? 0.75 : 0.05))
                                    .detectedCategories(categoryNames)
                                    .matchedCategory(decision.getMatchedCategory() != null ? decision.getMatchedCategory().name() : null)
                                    .findings(analysisResult.getFindings())
                                    .detectedPatterns(patterns)
                                    .blockReason(decision.getAction() == Action.BLOCK ? decision.getReason() : null)
                                    .policyReason(decision.getReason())
                                    .originalPayloadSize(body.length())
                                    .redactedPayloadSize(analysisResult.getSanitizedBody() != null ? analysisResult.getSanitizedBody().length() : 0)
                                    .safeBody(safeBodyLog)
                                    .redactedBody(decision.getAction() == Action.REDACT ? analysisResult.getSanitizedBody() : null)
                                    .executionTimeMs(executionTime)
                                    .anomalyScore(0.05)
                                    .build();

                            return saveLogAndAlert(logEntry)
                                    .map(savedLog -> {
                                        InspectionResponse response = InspectionResponse.builder()
                                                .decision(decision.getAction())
                                                .riskTier(decision.getRiskTier())
                                                .riskScore(logEntry.getRiskScore())
                                                .reason(decision.getReason())
                                                .detectedCategories(analysisResult.getDetectedCategories())
                                                .matchedCategory(decision.getMatchedCategory())
                                                .destinationStatus(decision.getDestinationStatus())
                                                .redactedBody(decision.getAction() == Action.REDACT ? analysisResult.getSanitizedBody() : null)
                                                .detectedPatterns(patterns)
                                                .blockReason(decision.getAction() == Action.BLOCK ? decision.getReason() : null)
                                                .executionTimeMs(executionTime)
                                                .logId(savedLog.getId())
                                                .build();

                                        log.info("Inspected request for {} | Decision: {} | Risk: {} | Reason: {}",
                                                destinationHost, decision.getAction(), decision.getRiskTier(), decision.getReason());

                                        return ResponseEntity.ok(response);
                                    });
                        })
                );
    }

    private Mono<InspectionLog> saveLogAndAlert(InspectionLog logEntry) {
        return inspectionLogRepository.save(logEntry)
                .onErrorResume(e -> {
                    log.warn("Mongo log persistence skipped or failed: {}. Assigning local synthetic ID.", e.getMessage());
                    logEntry.setId("log_" + System.currentTimeMillis());
                    return Mono.just(logEntry);
                })
                .flatMap(savedLog -> {
                    alertService.processAlert(savedLog).subscribe();
                    return Mono.just(savedLog);
                });
    }
}
