package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FindingDetail {
    private DetectionCategory category;
    private String findingType;
    private String maskedSnippet;
    private double confidence;
    private int count;
}
