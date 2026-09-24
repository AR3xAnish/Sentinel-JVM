package com.sentinel.gateway.repository;

import com.sentinel.gateway.model.OrganizationPolicy;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface PolicyRepository extends ReactiveMongoRepository<OrganizationPolicy, String> {
    Mono<OrganizationPolicy> findFirstByActiveTrue();
}
