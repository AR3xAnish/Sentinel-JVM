package com.sentinel.gateway.controller;

import com.sentinel.gateway.model.OrganizationPolicy;
import com.sentinel.gateway.service.PolicyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/policies")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class PolicyController {

    private final PolicyService policyService;

    @GetMapping("/active")
    public Mono<ResponseEntity<OrganizationPolicy>> getActivePolicy() {
        return policyService.getActivePolicy()
                .map(ResponseEntity::ok);
    }

    @GetMapping
    public Flux<OrganizationPolicy> getAllPolicies() {
        return policyService.getAllPolicies();
    }

    @PostMapping
    public Mono<ResponseEntity<OrganizationPolicy>> createPolicy(@RequestBody OrganizationPolicy policy) {
        return policyService.saveAndValidatePolicy(policy)
                .map(ResponseEntity::ok)
                .onErrorResume(IllegalArgumentException.class, e -> 
                        Mono.just(ResponseEntity.badRequest().build())
                );
    }

    @PutMapping("/{id}/activate")
    public Mono<ResponseEntity<OrganizationPolicy>> activatePolicy(@PathVariable String id) {
        return policyService.activatePolicy(id)
                .map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }
}
