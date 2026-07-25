package com.sentinel.gateway.repository;

import com.sentinel.gateway.model.AlertDocument;
import com.sentinel.gateway.model.RiskTier;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface AlertRepository extends ReactiveMongoRepository<AlertDocument, String> {
    Flux<AlertDocument> findByOrderByTimestampDesc(Pageable pageable);
    Flux<AlertDocument> findBySeverityOrderByTimestampDesc(RiskTier severity, Pageable pageable);
    Mono<Long> countByAcknowledgedFalse();
}
