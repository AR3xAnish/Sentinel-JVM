package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MlScoreRequest {
    private String destinationHost;
    private int payloadSize;
    private int hourOfDay;
    private int dayOfWeek;
    private int frequencyPerMinute;
    private double userHistoricalRisk;
}
