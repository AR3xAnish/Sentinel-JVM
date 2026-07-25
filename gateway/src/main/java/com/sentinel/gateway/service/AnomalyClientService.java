package com.sentinel.gateway.service;

import com.sentinel.gateway.model.MlScoreRequest;
import com.sentinel.gateway.model.MlScoreResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;

@Slf4j
@Service
public class AnomalyClientService {

    private final WebClient webClient;
    private final boolean enabled;

    public AnomalyClientService(
            @Value("${sentinel.ml-service.url:http://localhost:5000}") String mlServiceUrl,
            @Value("${sentinel.ml-service.enabled:true}") boolean enabled) {
        this.webClient = WebClient.builder()
                .baseUrl(mlServiceUrl)
        .build();
        this.enabled = enabled;
    }

    public Mono<MlScoreResponse> scoreRequest(MlScoreRequest scoreRequest) {
        if (!enabled) {
            return Mono.just(MlScoreResponse.builder()
                    .anomalyScore(0.05)
                    .isAnomaly(false)
                    .details(Map.of("status", "disabled"))
                    .build());
        }

        return webClient.post()
                .uri("/score")
                .bodyValue(scoreRequest)
                .retrieve()
                .bodyToMono(MlScoreResponse.class)
                .timeout(Duration.ofMillis(1500))
                .onErrorResume(e -> {
                    log.warn("ML Anomaly service call failed or timed out: {}. Fallback to default score 0.05", e.getMessage());
                    return Mono.just(MlScoreResponse.builder()
                            .anomalyScore(0.05)
                            .isAnomaly(false)
                            .details(Map.of("fallback", true, "error", e.getMessage()))
                            .build());
                });
    }
}
