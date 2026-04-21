package com.cuidatuslukas.repository;

import com.cuidatuslukas.model.CitizenReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CitizenReportRepository extends JpaRepository<CitizenReport, Long> {

    /** Cuenta reportes que mencionan la plataforma */
    @Query("""
        SELECT COUNT(r) FROM CitizenReport r WHERE
        LOWER(r.platformName) LIKE LOWER(CONCAT('%', :query, '%')) OR
        LOWER(r.rutAccount) LIKE LOWER(CONCAT('%', :query, '%'))
        """)
    long countByQuery(@Param("query") String query);

    /** Obtiene testimonios (details) relacionados con la búsqueda */
    @Query("""
        SELECT r FROM CitizenReport r WHERE
        (LOWER(r.platformName) LIKE LOWER(CONCAT('%', :query, '%')) OR
        LOWER(r.rutAccount) LIKE LOWER(CONCAT('%', :query, '%')))
        AND r.details IS NOT NULL
        ORDER BY r.createdAt DESC
        """)
    List<CitizenReport> findTestimoniosByQuery(@Param("query") String query);

    List<CitizenReport> findTop20ByOrderByCreatedAtDesc();
}
