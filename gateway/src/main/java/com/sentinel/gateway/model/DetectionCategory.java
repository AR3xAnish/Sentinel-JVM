package com.sentinel.gateway.model;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum DetectionCategory {
    CREDENTIALS_AND_SECRETS,
    CREDENTIAL, // Legacy backwards compatibility for MongoDB documents
    PERSONAL_DATA,
    FINANCIAL_DATA,
    SOURCE_CODE,
    BUSINESS_CONFIDENTIAL,
    HR_DATA,
    LEGAL_DATA;

    @JsonCreator
    public static DetectionCategory fromString(String value) {
        if (value == null || value.isBlank()) {
            return CREDENTIALS_AND_SECRETS;
        }
        String normalized = value.trim().toUpperCase();
        if ("CREDENTIAL".equals(normalized) || "CREDENTIALS".equals(normalized) || "SECRET".equals(normalized) || "SECRETS".equals(normalized)) {
            return CREDENTIALS_AND_SECRETS;
        }
        for (DetectionCategory cat : values()) {
            if (cat.name().equals(normalized)) {
                return cat;
            }
        }
        return CREDENTIALS_AND_SECRETS;
    }
}

