package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PolicyRule {

    private Action action; // ALLOW, REDACT, BLOCK
    private String description;
    
    @Builder.Default
    private double threshold = 0.5;

    @Builder.Default
    private Map<String, Action> destinationOverrides = new HashMap<>();
}
