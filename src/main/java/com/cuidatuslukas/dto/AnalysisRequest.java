package com.cuidatuslukas.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class AnalysisRequest {

    @NotBlank(message = "La consulta no puede estar vacía")
    @Size(min = 3, max = 500, message = "La consulta debe tener entre 3 y 500 caracteres")
    private String query;
}
