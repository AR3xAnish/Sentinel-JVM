package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "security_alerts")
public class AlertDocument {
    @Id
    private String id;
    private String logId;
    private Instant timestamp;
    private RiskTier severity;
    private String title;
    private String summary;
    private String destinationHost;
    private String clientIp;
    private List<String> detectedPatterns;
    private Action actionTaken;
    private boolean acknowledged;
}
