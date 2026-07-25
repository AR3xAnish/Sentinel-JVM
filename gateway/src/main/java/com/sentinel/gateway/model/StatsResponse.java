package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StatsResponse {
    private long totalRequests;
    private long allowedCount;
    private long redactedCount;
    private long blockedCount;
    private long highRiskAlertsCount;
    private double averageLatencyMs;
    private Map<String, Long> riskTierDistribution;
    private Map<String, Long> topTargetDomains;
    private List<TimeSeriesPoint> usageTrends;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TimeSeriesPoint {
        private String timestamp;
        private long total;
        private long allowed;
        private long redacted;
        private long blocked;
    }
}
