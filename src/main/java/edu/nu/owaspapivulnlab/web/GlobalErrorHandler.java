package edu.nu.owaspapivulnlab.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

// VULNERABILITY(API7): overly verbose error responses
// FIX #8: Sanitize error responses to avoid leaking sensitive information
@ControllerAdvice
public class GlobalErrorHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalErrorHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> all(Exception e) {
        log.error("Internal error: {}", e.getMessage(), e); // Log full details server-side
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "internal_error");
        errorMap.put("message", "An unexpected error occurred. Please contact support.");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorMap);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> db(DataAccessException e) {
        log.error("Database error: {}", e.getMessage(), e);
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "database_error");
        errorMap.put("message", "A database error occurred.");
        return ResponseEntity.status(500).body(errorMap);
    }
}
