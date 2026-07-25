package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MlScoreResponse {
    private Double anomalyScore;
    private Boolean isAnomaly;
    private Map<String, Object> details;
}
