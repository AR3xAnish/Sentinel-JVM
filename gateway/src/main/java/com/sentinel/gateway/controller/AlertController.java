package com.sentinel.gateway.controller;

import com.sentinel.gateway.model.AlertDocument;
import com.sentinel.gateway.repository.AlertRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AlertController {

    private final AlertRepository alertRepository;

    @GetMapping
    public Flux<AlertDocument> getAlerts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int limit) {
        return alertRepository.findByOrderByTimestampDesc(PageRequest.of(page, limit));
    }

    @PostMapping("/webhook-mock")
    public Mono<ResponseEntity<Map<String, String>>> receiveMockWebhook(@RequestBody Map<String, Object> payload) {
        log.info("Received Mock Alert Webhook Payload: {}", payload);
        return Mono.just(ResponseEntity.ok(Map.of("status", "received", "alertId", String.valueOf(payload.get("alertId")))));
    }
}
