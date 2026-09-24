package com.sentinel.gateway.config;

import com.sentinel.gateway.model.Action;
import com.sentinel.gateway.model.DetectionCategory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.mongodb.core.convert.MongoCustomConversions;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Configuration
public class MongoConfig {

    @Bean
    public MongoCustomConversions mongoCustomConversions() {
        List<Converter<?, ?>> converters = new ArrayList<>();
        converters.add(new StringToActionConverter());
        converters.add(new StringToDetectionCategoryConverter());
        return new MongoCustomConversions(converters);
    }

    @ReadingConverter
    public static class StringToActionConverter implements Converter<String, Action> {
        @Override
        public Action convert(String source) {
            if (source == null || source.isBlank()) {
                return Action.ALLOW;
            }
            String norm = source.trim().toUpperCase();
            if ("MASK".equals(norm)) {
                return Action.REDACT;
            }
            if ("MONITOR".equals(norm) || "LOG".equals(norm) || "FLAG".equals(norm)) {
                return Action.ALLOW;
            }
            try {
                return Action.valueOf(norm);
            } catch (IllegalArgumentException e) {
                log.warn("Unrecognized Action enum string in MongoDB: '{}'. Defaulting to ALLOW.", source);
                return Action.ALLOW;
            }
        }
    }

    @ReadingConverter
    public static class StringToDetectionCategoryConverter implements Converter<String, DetectionCategory> {
        @Override
        public DetectionCategory convert(String source) {
            if (source == null || source.isBlank()) {
                return DetectionCategory.CREDENTIALS_AND_SECRETS;
            }
            String norm = source.trim().toUpperCase();
            if ("CREDENTIAL".equals(norm) || "CREDENTIALS".equals(norm) || "SECRET".equals(norm) || "SECRETS".equals(norm)) {
                return DetectionCategory.CREDENTIALS_AND_SECRETS;
            }
            try {
                return DetectionCategory.valueOf(norm);
            } catch (IllegalArgumentException e) {
                log.warn("Unrecognized DetectionCategory enum string in MongoDB: '{}'. Defaulting to CREDENTIALS_AND_SECRETS.", source);
                return DetectionCategory.CREDENTIALS_AND_SECRETS;
            }
        }
    }
}

