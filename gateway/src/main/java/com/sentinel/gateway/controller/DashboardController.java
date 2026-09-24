package com.sentinel.gateway.controller;

import com.sentinel.gateway.model.Action;
import com.sentinel.gateway.model.InspectionLog;
import com.sentinel.gateway.model.RiskTier;
import com.sentinel.gateway.model.StatsResponse;
import com.sentinel.gateway.repository.InspectionLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class DashboardController {

    private final InspectionLogRepository inspectionLogRepository;

    @GetMapping("/events")
    public Flux<InspectionLog> getEvents(
            @RequestParam(required = false) String riskTier,
            @RequestParam(required = false) String decision,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int limit) {

        Pageable pageable = PageRequest.of(page, limit);

        Flux<InspectionLog> flux;
        if (riskTier != null && !riskTier.isBlank()) {
            try {
                RiskTier tier = RiskTier.valueOf(riskTier.toUpperCase());
                flux = inspectionLogRepository.findByRiskTierOrderByTimestampDesc(tier, pageable);
            } catch (IllegalArgumentException e) {
                flux = inspectionLogRepository.findByOrderByTimestampDesc(pageable);
            }
        } else if (decision != null && !decision.isBlank()) {
            try {
                Action act = Action.valueOf(decision.toUpperCase());
                flux = inspectionLogRepository.findByDecisionOrderByTimestampDesc(act, pageable);
            } catch (IllegalArgumentException e) {
                flux = inspectionLogRepository.findByOrderByTimestampDesc(pageable);
            }
        } else {
            flux = inspectionLogRepository.findByOrderByTimestampDesc(pageable);
        }

        return flux.onErrorResume(e -> {
            log.warn("Error retrieving events from MongoDB: {}. Returning empty stream.", e.getMessage());
            return Flux.empty();
        });
    }

    @GetMapping("/stats")
    public Mono<StatsResponse> getStats() {
        return inspectionLogRepository.findAll()
                .collectList()
                .map(logs -> {
                    if (logs == null || logs.isEmpty()) {
                        return createEmptyStats();
                    }

                    long total = logs.size();
                    long allowed = logs.stream().filter(l -> l.getDecision() == Action.ALLOW).count();
                    long redacted = logs.stream().filter(l -> l.getDecision() == Action.REDACT || l.getDecision() == Action.MASK).count();
                    long blocked = logs.stream().filter(l -> l.getDecision() == Action.BLOCK).count();
                    long highRisk = logs.stream().filter(l -> l.getRiskTier() == RiskTier.HIGH || l.getRiskTier() == RiskTier.CRITICAL).count();

                    double avgLatency = logs.stream()
                            .mapToLong(l -> l.getExecutionTimeMs() != null ? l.getExecutionTimeMs() : 0L)
                            .average().orElse(0.0);

                    Map<String, Long> riskDist = logs.stream()
                            .collect(Collectors.groupingBy(l -> l.getRiskTier() != null ? l.getRiskTier().name() : "LOW", Collectors.counting()));

                    Map<String, Long> topDomains = logs.stream()
                            .collect(Collectors.groupingBy(l -> l.getDestinationHost() != null ? l.getDestinationHost() : "unknown", Collectors.counting()));

                    Map<String, Long> categoryMap = new HashMap<>();
                    logs.forEach(l -> {
                        if (l.getDetectedCategories() != null) {
                            for (String cat : l.getDetectedCategories()) {
                                categoryMap.put(cat, categoryMap.getOrDefault(cat, 0L) + 1);
                            }
                        }
                    });

                    // Time series points grouped by hour
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());
                    Map<String, List<InspectionLog>> groupedByTime = logs.stream()
                            .collect(Collectors.groupingBy(l -> l.getTimestamp() != null ? formatter.format(l.getTimestamp()) : "Now"));

                    List<StatsResponse.TimeSeriesPoint> trends = new ArrayList<>();
                    groupedByTime.forEach((timeStr, list) -> {
                        long tAllow = list.stream().filter(l -> l.getDecision() == Action.ALLOW).count();
                        long tRedact = list.stream().filter(l -> l.getDecision() == Action.REDACT || l.getDecision() == Action.MASK).count();
                        long tBlock = list.stream().filter(l -> l.getDecision() == Action.BLOCK).count();
                        trends.add(StatsResponse.TimeSeriesPoint.builder()
                                .timestamp(timeStr)
                                .total(list.size())
                                .allowed(tAllow)
                                .redacted(tRedact)
                                .blocked(tBlock)
                                .build());
                    });

                    return StatsResponse.builder()
                            .totalRequests(total)
                            .allowedCount(allowed)
                            .redactedCount(redacted)
                            .blockedCount(blocked)
                            .highRiskAlertsCount(highRisk)
                            .averageLatencyMs(avgLatency)
                            .riskTierDistribution(riskDist)
                            .topTargetDomains(topDomains)
                            .topDetectedCategories(categoryMap)
                            .usageTrends(trends)
                            .build();
                })
                .onErrorResume(e -> {
                    log.warn("Error calculating stats from MongoDB: {}. Returning empty stats fallback.", e.getMessage());
                    return Mono.just(createEmptyStats());
                });
    }

    private StatsResponse createEmptyStats() {
        return StatsResponse.builder()
                .totalRequests(0)
                .allowedCount(0)
                .redactedCount(0)
                .blockedCount(0)
                .highRiskAlertsCount(0)
                .averageLatencyMs(0.0)
                .riskTierDistribution(Map.of("LOW", 0L, "MEDIUM", 0L, "HIGH", 0L, "CRITICAL", 0L))
                .topTargetDomains(Map.of())
                .topDetectedCategories(Map.of())
                .usageTrends(Collections.emptyList())
                .build();
    }
}
