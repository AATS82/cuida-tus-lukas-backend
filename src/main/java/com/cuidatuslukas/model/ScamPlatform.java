package com.cuidatuslukas.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scam_platforms", indexes = {
    @Index(name = "idx_url", columnList = "url"),
    @Index(name = "idx_rut", columnList = "rut_ruc")
})
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class ScamPlatform {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Nombre con el que se presenta la plataforma */
    @Column(nullable = false, length = 255)
    private String name;

    /** URL del sitio fraudulento */
    @Column(length = 500)
    private String url;

    /** RUT o identificador fiscal chileno */
    @Column(name = "rut_ruc", length = 30)
    private String rutRuc;

    /** Descripción del fraude */
    @Column(length = 2000)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false)
    private RiskLevel riskLevel;

    /** Fuente: CMF_ALERT, CITIZEN_REPORT, ADMIN, NEWS */
    @Column(length = 50)
    private String source;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        createdAt = LocalDateTime.now();
    }
}
