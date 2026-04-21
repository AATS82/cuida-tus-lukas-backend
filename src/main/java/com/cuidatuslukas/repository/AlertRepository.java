package com.cuidatuslukas.repository;

import com.cuidatuslukas.model.Alert;
import com.cuidatuslukas.model.RiskLevel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {

    List<Alert> findTop10ByOrderByCreatedAtDesc();

    List<Alert> findByRiskLevelOrderByCreatedAtDesc(RiskLevel riskLevel);
}
