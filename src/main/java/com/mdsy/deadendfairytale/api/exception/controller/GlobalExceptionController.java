package com.mdsy.deadendfairytale.api.exception.controller;

import com.mdsy.deadendfairytale.api.exception.InfoNotFoundException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionController {
    @ExceptionHandler(InfoNotFoundException.class)
    public ResponseEntity<?> infoNotFoundException(final InfoNotFoundException e) {

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", false);
        errorResponse.put("message", e.getMessage());

        return ResponseEntity.badRequest().body(errorResponse);
    }
}
