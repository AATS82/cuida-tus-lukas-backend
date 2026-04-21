package com.cuidatuslukas.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Data
public class ReportRequest {

    @NotBlank(message = "El nombre de la plataforma es requerido")
    @Size(max = 255)
    private String platformName;

    @Size(max = 100)
    private String rutAccount;

    @Size(max = 3000)
    private String details;

    private List<String> channels;
}
