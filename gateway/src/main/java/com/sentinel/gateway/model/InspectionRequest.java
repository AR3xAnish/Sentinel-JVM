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
public class InspectionRequest {
    private String destinationHost;
    private String requestPath;
    private String method;
    private String clientIp;
    private String userId;
    private String body;
    private Map<String, String> headers;
    private Long timestamp;
}
