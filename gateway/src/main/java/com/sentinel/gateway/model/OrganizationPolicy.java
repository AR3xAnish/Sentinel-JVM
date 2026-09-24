package com.sentinel.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "policies")
public class OrganizationPolicy {

    @Id
    private String id;
    private String organizationName;
    private int version;
    private boolean active;

    @Builder.Default
    private List<String> approvedDestinations = new ArrayList<>();

    @Builder.Default
    private List<String> restrictedDestinations = new ArrayList<>();

    @Builder.Default
    private List<String> unapprovedDestinations = new ArrayList<>();

    @Builder.Default
    private Map<String, PolicyRule> rules = new HashMap<>();

    @Builder.Default
    private Action unapprovedDestinationAction = Action.BLOCK;

    public PolicyRule getCategoryRule(DetectionCategory category) {
        if (rules == null || category == null) return null;
        return rules.get(category.name());
    }

    public void setCategoryRule(DetectionCategory category, PolicyRule rule) {
        if (rules == null) rules = new HashMap<>();
        if (category != null) {
            rules.put(category.name(), rule);
        }
    }
}
