package com.sentinel.gateway.repository;

import com.sentinel.gateway.model.Action;
import com.sentinel.gateway.model.InspectionLog;
import com.sentinel.gateway.model.RiskTier;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface InspectionLogRepository extends ReactiveMongoRepository<InspectionLog, String> {
    Flux<InspectionLog> findByOrderByTimestampDesc(Pageable pageable);
    Flux<InspectionLog> findByRiskTierOrderByTimestampDesc(RiskTier riskTier, Pageable pageable);
    Flux<InspectionLog> findByDecisionOrderByTimestampDesc(Action decision, Pageable pageable);
    Mono<Long> countByDecision(Action decision);
    Mono<Long> countByRiskTier(RiskTier riskTier);
}
