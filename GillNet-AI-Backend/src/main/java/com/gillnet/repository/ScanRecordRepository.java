package com.gillnet.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.gillnet.model.ScanRecord;

public interface ScanRecordRepository extends MongoRepository<ScanRecord, String> {

    List<ScanRecord> findByUserIdOrderByTimestampDesc(String userId);

    List<ScanRecord> findAllByOrderByTimestampDesc();

    long countByRiskLevel(String riskLevel);

    long countByResult(String result);
}
