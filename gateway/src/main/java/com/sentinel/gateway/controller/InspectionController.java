package com.sentinel.gateway.controller;

import com.sentinel.gateway.model.*;
import com.sentinel.gateway.repository.InspectionLogRepository;
import com.sentinel.gateway.service.AlertService;
import com.sentinel.gateway.service.AnomalyClientService;
import com.sentinel.gateway.service.RiskEvaluatorService;
import com.sentinel.gateway.service.SecretDetectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.LocalTime;

@Slf4j
@RestController
@RequestMapping("/api/inspect")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class InspectionController {

    private final SecretDetectorService secretDetectorService;
    private final AnomalyClientService anomalyClientService;
    private final RiskEvaluatorService riskEvaluatorService;
    private final InspectionLogRepository inspectionLogRepository;
    private final AlertService alertService;

    @PostMapping
    public Mono<ResponseEntity<InspectionResponse>> inspectPayload(@RequestBody InspectionRequest request) {
        long startTime = System.currentTimeMillis();

        String body = request.getBody() != null ? request.getBody() : "";
        int payloadSize = body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        int hourOfDay = LocalTime.now().getHour();
        int dayOfWeek = java.time.LocalDate.now().getDayOfWeek().getValue();

        // 1. Inspect secrets in body
        SecretDetectorService.DetectionResult secretResult = secretDetectorService.inspectBody(body);

        // 2. Prepare ML Score Request
        MlScoreRequest mlRequest = MlScoreRequest.builder()
                .destinationHost(request.getDestinationHost())
                .payloadSize(payloadSize)
                .hourOfDay(hourOfDay)
                .dayOfWeek(dayOfWeek)
                .frequencyPerMinute(5) // default estimated frequency
                .userHistoricalRisk(0.1)
                .build();

        // 3. Call ML Anomaly Service and evaluate risk
        return anomalyClientService.scoreRequest(mlRequest)
                .flatMap(mlResponse -> {
                    Double anomalyScore = mlResponse.getAnomalyScore();

                    // Evaluate combined risk
                    RiskEvaluatorService.EvaluationResult eval =
                            riskEvaluatorService.evaluateRisk(secretResult, anomalyScore);

                    long executionTime = System.currentTimeMillis() - startTime;

                    String sanitizedBody = eval.getAction() == Action.REDACT ? secretResult.getSanitizedBody() : body;

                    // Build MongoDB log document
                    InspectionLog logEntry = InspectionLog.builder()
                            .timestamp(Instant.now())
                            .destinationHost(request.getDestinationHost() != null ? request.getDestinationHost() : "unknown")
                            .requestPath(request.getRequestPath() != null ? request.getRequestPath() : "/")
                            .method(request.getMethod() != null ? request.getMethod() : "POST")
                            .clientIp(request.getClientIp() != null ? request.getClientIp() : "127.0.0.1")
                            .userId(request.getUserId() != null ? request.getUserId() : "anonymous")
                            .decision(eval.getAction())
                            .riskTier(eval.getRiskTier())
                            .riskScore(eval.getCompositeRiskScore())
                            .detectedPatterns(secretResult.getDetectedPatterns())
                            .blockReason(eval.getReason())
                            .originalPayloadSize(payloadSize)
                            .redactedPayloadSize(sanitizedBody.length())
                            .executionTimeMs(executionTime)
                            .anomalyScore(anomalyScore)
                            .build();

                    // Save log entry to Mongo & trigger alerts asynchronously
                    return saveLogAndAlert(logEntry)
                            .map(savedLog -> {
                                InspectionResponse response = InspectionResponse.builder()
                                        .decision(eval.getAction())
                                        .riskTier(eval.getRiskTier())
                                        .riskScore(eval.getCompositeRiskScore())
                                        .redactedBody(eval.getAction() == Action.REDACT ? sanitizedBody : null)
                                        .detectedPatterns(secretResult.getDetectedPatterns())
                                        .blockReason(eval.getAction() == Action.BLOCK ? eval.getReason() : null)
                                        .executionTimeMs(executionTime)
                                        .logId(savedLog.getId())
                                        .build();

                                log.info("Inspected request for {} | Decision: {} | Risk: {} | Time: {}ms",
                                        request.getDestinationHost(), eval.getAction(), eval.getRiskTier(), executionTime);

                                return ResponseEntity.ok(response);
                            });
                });
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
