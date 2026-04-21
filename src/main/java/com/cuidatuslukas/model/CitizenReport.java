package com.cuidatuslukas.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "citizen_reports")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class CitizenReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Nombre de la plataforma/entidad denunciada */
    @Column(name = "platform_name", nullable = false, length = 255)
    private String platformName;

    /** RUT o cuenta bancaria a la que pidieron transferir */
    @Column(name = "rut_account", length = 100)
    private String rutAccount;

    /** Detalle libre del ciudadano */
    @Column(length = 3000)
    private String details;

    /** Canales por los que fue contactado: WHATSAPP, INSTAGRAM, etc. */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "report_channels",
        joinColumns = @JoinColumn(name = "report_id")
    )
    @Column(name = "channel", length = 50)
    private List<String> channels;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        createdAt = LocalDateTime.now();
    }
}
