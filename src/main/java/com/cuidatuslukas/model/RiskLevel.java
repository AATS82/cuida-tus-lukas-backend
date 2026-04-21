package com.cuidatuslukas.model;

public enum RiskLevel {
    SAFE,     // Bajo o nulo riesgo
    CAUTION,  // Señales de alerta — investigar más
    CRITICAL, // Alto riesgo confirmado
    UNKNOWN   // No se pudo determinar
}
