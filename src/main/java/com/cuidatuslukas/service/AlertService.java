package com.cuidatuslukas.service;

import com.cuidatuslukas.dto.AlertDto;
import com.cuidatuslukas.repository.AlertRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AlertService {

    private final AlertRepository alertRepository;

    public List<AlertDto> getRecentAlerts() {
        return alertRepository.findTop10ByOrderByCreatedAtDesc()
                .stream()
                .map(AlertDto::from)
                .toList();
    }

    public List<AlertDto> getAllAlerts() {
        return alertRepository.findAll()
                .stream()
                .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()))
                .map(AlertDto::from)
                .toList();
    }
}
