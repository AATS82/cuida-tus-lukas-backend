package com.cuidatuslukas.repository;

import com.cuidatuslukas.model.ScamPlatform;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ScamPlatformRepository extends JpaRepository<ScamPlatform, Long> {

    /** Busca por URL exacta o que la contenga */
    @Query("SELECT s FROM ScamPlatform s WHERE LOWER(s.url) LIKE LOWER(CONCAT('%', :query, '%'))")
    List<ScamPlatform> findByUrlContaining(@Param("query") String query);

    /** Busca por RUT */
    Optional<ScamPlatform> findByRutRuc(String rutRuc);

    /** Busca por nombre (parcial, insensible a mayúsculas) */
    @Query("SELECT s FROM ScamPlatform s WHERE LOWER(s.name) LIKE LOWER(CONCAT('%', :name, '%'))")
    List<ScamPlatform> findByNameContaining(@Param("name") String name);

    /** Busca en URL, RUT o nombre — búsqueda global */
    @Query("""
        SELECT s FROM ScamPlatform s WHERE
        LOWER(s.url) LIKE LOWER(CONCAT('%', :q, '%')) OR
        LOWER(s.name) LIKE LOWER(CONCAT('%', :q, '%')) OR
        LOWER(s.rutRuc) LIKE LOWER(CONCAT('%', :q, '%'))
        """)
    List<ScamPlatform> searchAll(@Param("q") String query);

    boolean existsByRutRuc(String rutRuc);
    boolean existsByUrl(String url);
    boolean existsByName(String name);
}
