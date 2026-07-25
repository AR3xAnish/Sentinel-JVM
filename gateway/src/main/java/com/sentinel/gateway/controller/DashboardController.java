package com.sentinel.gateway.controller;

import com.sentinel.gateway.model.Action;
import com.sentinel.gateway.model.InspectionLog;
import com.sentinel.gateway.model.RiskTier;
import com.sentinel.gateway.model.StatsResponse;
import com.sentinel.gateway.repository.InspectionLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

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

        if (riskTier != null && !riskTier.isBlank()) {
            try {
                RiskTier tier = RiskTier.valueOf(riskTier.toUpperCase());
                return inspectionLogRepository.findByRiskTierOrderByTimestampDesc(tier, pageable);
            } catch (IllegalArgumentException e) {
                // Ignore invalid tier filter
            }
        }

        if (decision != null && !decision.isBlank()) {
            try {
                Action act = Action.valueOf(decision.toUpperCase());
                return inspectionLogRepository.findByDecisionOrderByTimestampDesc(act, pageable);
            } catch (IllegalArgumentException e) {
                // Ignore invalid decision filter
            }
        }

        return inspectionLogRepository.findByOrderByTimestampDesc(pageable);
    }

    @GetMapping("/stats")
    public Mono<StatsResponse> getStats() {
        return inspectionLogRepository.findAll()
                .collectList()
                .map(logs -> {
                    if (logs.isEmpty()) {
                        return createEmptyStats();
                    }

                    long total = logs.size();
                    long allowed = logs.stream().filter(l -> l.getDecision() == Action.ALLOW).count();
                    long redacted = logs.stream().filter(l -> l.getDecision() == Action.REDACT).count();
                    long blocked = logs.stream().filter(l -> l.getDecision() == Action.BLOCK).count();
                    long highRisk = logs.stream().filter(l -> l.getRiskTier() == RiskTier.HIGH || l.getRiskTier() == RiskTier.CRITICAL).count();

                    double avgLatency = logs.stream()
                            .mapToLong(l -> l.getExecutionTimeMs() != null ? l.getExecutionTimeMs() : 0L)
                            .average().orElse(0.0);

                    Map<String, Long> riskDist = logs.stream()
                            .collect(Collectors.groupingBy(l -> l.getRiskTier().name(), Collectors.counting()));

                    Map<String, Long> topDomains = logs.stream()
                            .collect(Collectors.groupingBy(l -> l.getDestinationHost() != null ? l.getDestinationHost() : "unknown", Collectors.counting()));

                    // Time series points grouped by hour
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());
                    Map<String, List<InspectionLog>> groupedByTime = logs.stream()
                            .collect(Collectors.groupingBy(l -> l.getTimestamp() != null ? formatter.format(l.getTimestamp()) : "Now"));

                    List<StatsResponse.TimeSeriesPoint> trends = new ArrayList<>();
                    groupedByTime.forEach((timeStr, list) -> {
                        long tAllow = list.stream().filter(l -> l.getDecision() == Action.ALLOW).count();
                        long tRedact = list.stream().filter(l -> l.getDecision() == Action.REDACT).count();
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
                            .usageTrends(trends)
                            .build();
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
                .usageTrends(Collections.emptyList())
                .build();
    }
}
