package com.securevault.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * REST controller for system health monitoring.
 *
 * Provides health check endpoints for:
 * - Application uptime monitoring
 * - Database connectivity verification
 * - Load balancer health checks
 *
 * This endpoint is typically used by:
 * - Kubernetes liveness/readiness probes
 * - Load balancers for traffic routing
 * - Monitoring systems for uptime tracking
 *
 * NOTE: This endpoint does not require authentication as it's
 * intended for infrastructure-level health checks.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class HealthController {

    private final DataSource dataSource;

    /**
     * Returns the health status of the application.
     *
     * Checks:
     * - Application is running
     * - Database connection is healthy
     *
     * @return Map with "status", "timestamp", and "database" fields
     *         Returns 503 if database is unavailable
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("timestamp", LocalDateTime.now());

        boolean dbHealthy = checkDatabase();
        response.put("database", dbHealthy ? "UP" : "DOWN");

        if (!dbHealthy) {
            log.error("Database health check failed");
            return ResponseEntity.status(503).body(response);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Verifies database connectivity by checking connection validity.
     *
     * Uses a 5-second timeout for connection validation.
     *
     * @return true if database is reachable, false otherwise
     */
    private boolean checkDatabase() {
        try (Connection connection = dataSource.getConnection()) {
            return connection.isValid(5);
        } catch (Exception e) {
            log.error("Database connection check failed: {}", e.getMessage());
            return false;
        }
    }
}