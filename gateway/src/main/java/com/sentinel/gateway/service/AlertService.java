package com.sentinel.gateway.service;

import com.sentinel.gateway.model.AlertDocument;
import com.sentinel.gateway.model.InspectionLog;
import com.sentinel.gateway.model.RiskTier;
import com.sentinel.gateway.repository.AlertRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

@Slf4j
@Service
public class AlertService {

    private final AlertRepository alertRepository;
    private final WebClient webClient;
    private final String webhookUrl;

    public AlertService(
            AlertRepository alertRepository,
            @Value("${sentinel.alerting.webhook-url:http://localhost:8080/api/alerts/webhook-mock}") String webhookUrl) {
        this.alertRepository = alertRepository;
        this.webhookUrl = webhookUrl;
        this.webClient = WebClient.create();
    }

    public Mono<AlertDocument> processAlert(InspectionLog logEntry) {
        if (logEntry.getRiskTier() != RiskTier.HIGH && logEntry.getRiskTier() != RiskTier.CRITICAL) {
            return Mono.empty();
        }

        String title = String.format("[%s ALERT] Shadow AI Policy Violation on %s",
                logEntry.getRiskTier(), logEntry.getDestinationHost());

        String summary = String.format("Action: %s | Source: %s | Risk Score: %.2f | Patterns: %s | Reason: %s",
                logEntry.getDecision(),
                logEntry.getClientIp(),
                logEntry.getRiskScore(),
                logEntry.getDetectedPatterns() != null ? String.join(", ", logEntry.getDetectedPatterns()) : "None",
                logEntry.getBlockReason() != null ? logEntry.getBlockReason() : "Policy rule match");

        AlertDocument alert = AlertDocument.builder()
                .logId(logEntry.getId())
                .timestamp(Instant.now())
                .severity(logEntry.getRiskTier())
                .title(title)
                .summary(summary)
                .destinationHost(logEntry.getDestinationHost())
                .clientIp(logEntry.getClientIp())
                .detectedPatterns(logEntry.getDetectedPatterns())
                .actionTaken(logEntry.getDecision())
                .acknowledged(false)
                .build();

        log.warn("DISPATCHING SECURITY ALERT: {} -> {}", title, summary);

        // Save alert to database and trigger async Webhook notification
        return alertRepository.save(alert)
                .doOnSuccess(savedAlert -> sendWebhookNotification(savedAlert).subscribe());
    }

    private Mono<Void> sendWebhookNotification(AlertDocument alert) {
        if (webhookUrl == null || webhookUrl.isBlank() || webhookUrl.contains("webhook-mock")) {
            log.info("Mock Webhook Alert triggered for Alert ID: {}", alert.getId());
            return Mono.empty();
        }

        Map<String, Object> payload = Map.of(
                "alertId", alert.getId(),
                "severity", alert.getSeverity(),
                "title", alert.getTitle(),
                "summary", alert.getSummary(),
                "destination", alert.getDestinationHost(),
                "timestamp", alert.getTimestamp().toString()
        );

        return webClient.post()
                .uri(webhookUrl)
                .bodyValue(payload)
                .retrieve()
                .bodyToMono(Void.class)
                .onErrorResume(e -> {
                    log.error("Failed to deliver alert webhook notification: {}", e.getMessage());
                    return Mono.empty();
                });
    }
}
