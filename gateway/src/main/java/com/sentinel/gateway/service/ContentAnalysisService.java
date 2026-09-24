package com.sentinel.gateway.service;

import com.sentinel.gateway.model.ContentAnalysisResult;
import com.sentinel.gateway.model.DetectionCategory;
import com.sentinel.gateway.model.FindingDetail;
import com.sentinel.gateway.model.MlScoreRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class ContentAnalysisService {

    private final SecretDetectorService secretDetectorService;
    private final AnomalyClientService anomalyClientService;

    public Mono<ContentAnalysisResult> analyze(String body, String destinationHost) {
        String host = destinationHost != null ? destinationHost.toLowerCase() : "unknown";

        // 1. Run deterministic content detection (Secrets, PII, Financial, Source Code, Confidential, HR, Legal)
        ContentAnalysisResult result = secretDetectorService.analyzeContent(body, host);

        int payloadSize = body != null ? body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length : 0;
        int hourOfDay = LocalTime.now().getHour();
        int dayOfWeek = java.time.LocalDate.now().getDayOfWeek().getValue();

        MlScoreRequest mlRequest = MlScoreRequest.builder()
                .destinationHost(host)
                .payloadSize(payloadSize)
                .hourOfDay(hourOfDay)
                .dayOfWeek(dayOfWeek)
                .frequencyPerMinute(5)
                .userHistoricalRisk(0.1)
                .build();

        // 2. Call ML service to augment semantic/anomaly classification
        return anomalyClientService.scoreRequest(mlRequest)
                .map(mlResponse -> {
                    Double mlScore = mlResponse.getAnomalyScore();
                    if (mlScore != null && mlScore > 0.70) {
                        // High ML semantic anomaly score can boost confidential confidence
                        if (result.getBusinessConfidentialConfidence() < 0.6) {
                            result.setBusinessConfidentialConfidence(0.65);
                        }
                    }
                    return result;
                })
                .onErrorResume(e -> {
                    log.debug("ML service call failed: {}. Continuing with deterministic content analysis.", e.getMessage());
                    return Mono.just(result);
                });
    }
}
