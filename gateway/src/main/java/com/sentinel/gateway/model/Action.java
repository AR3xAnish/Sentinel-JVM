package com.sentinel.gateway.model;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum Action {
    ALLOW,
    REDACT,
    BLOCK,
    MASK,
    MONITOR,
    LOG,
    FLAG,
    ALERT;

    @JsonCreator
    public static Action fromString(String value) {
        if (value == null || value.isBlank()) {
            return ALLOW;
        }
        String normalized = value.trim().toUpperCase();
        for (Action action : values()) {
            if (action.name().equals(normalized)) {
                return action;
            }
        }
        if ("MASK".equals(normalized)) return REDACT;
        if ("MONITOR".equals(normalized) || "LOG".equals(normalized) || "FLAG".equals(normalized)) return ALLOW;
        return ALLOW;
    }
}


