package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContentAnalysisResult {

    @Builder.Default
    private Set<DetectionCategory> detectedCategories = new HashSet<>();

    @Builder.Default
    private List<FindingDetail> findings = new ArrayList<>();

    @Builder.Default
    private Set<String> secretTypes = new HashSet<>();

    private int piiCount;
    private int financialDataIndicators;

    private double sourceCodeConfidence;
    private double businessConfidentialConfidence;
    private double hrDataIndicators;
    private double legalDataIndicators;

    private String rawBody;
    private String sanitizedBody;
    private String destinationHost;
    private String destinationService;
    private boolean destinationApproved;
}
