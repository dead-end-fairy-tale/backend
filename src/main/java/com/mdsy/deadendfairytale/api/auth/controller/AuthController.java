package com.mdsy.deadendfairytale.api.auth.controller;

import com.mdsy.deadendfairytale.api.auth.dto.request.AuthRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.response.AuthResponseDTO;
import com.mdsy.deadendfairytale.api.auth.service.AuthService;
import com.mdsy.deadendfairytale.api.exception.DuplicateUserException;
import com.mdsy.deadendfairytale.api.exception.LoginFailException;
import com.mdsy.deadendfairytale.jwt.CustomUserDetails;
import com.mdsy.deadendfairytale.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtService jwtService;
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody AuthRequestDTO requestDTO) {
        log.info("/api/auth/signup : POST");
        log.info("requestDTO : {}", requestDTO);

        boolean isSuccess = authService.Signup(requestDTO);

        Map<String, Object> responseDTO = new HashMap<>();
        responseDTO.put("status", isSuccess);
        responseDTO.put("message", "회원가입에 성공했습니다.");


        return ResponseEntity.ok().body(responseDTO);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequestDTO requestDTO) {
        log.info("/api/auth/login : POST");
        log.info("requestDTO : {}", requestDTO);

        AuthResponseDTO responseDTO = authService.login(requestDTO);

        return ResponseEntity.ok().body(responseDTO);
    }

    @PostMapping("/token")
    public ResponseEntity<?> refreshToken(@RequestParam String accessToken) {
        log.info("/api/auth/token : POST");
        log.info("accessToken: {}", accessToken);
        
        if (accessToken == null || accessToken.trim().isEmpty()) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", false);
            errorResponse.put("message", "액세스 토큰이 필요합니다.");
            return ResponseEntity.badRequest().body(errorResponse);
        }
        
        try {
            AuthResponseDTO responseDTO = authService.refreshTokenByAccessToken(accessToken);
            return ResponseEntity.ok().body(responseDTO);
        } catch (Exception e) {
            log.error("토큰 갱신 실패: {}", e.getMessage());
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", false);
            errorResponse.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }

    /**
     * 현재 인증된 사용자 정보 조회
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
        // userDetails가 null인 경우 (인증되지 않은 사용자)
        if (userDetails == null) {
            log.warn("Unauthenticated request to /api/auth/me");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        String token = userDetails.getAccessToken();
        
        // 토큰이 null이거나 비어있는 경우
        if (token == null || token.trim().isEmpty()) {
            log.warn("토큰이 비어있거나 유저정보가 없습니다!: {}", userDetails.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        try {
            if (jwtService.validateToken(token)) {
                String username = jwtService.extractUsername(token);
                return ResponseEntity.ok(Map.of("username", username));
            } else {
                log.warn("Invalid token for user: {}", userDetails.getUsername());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        } catch (Exception e) {
            log.error("Error validating token: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @ExceptionHandler(DuplicateUserException.class)
    public ResponseEntity<?> handlerDuplicateUserException(DuplicateUserException e) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", false);
        errorResponse.put("message", e.getMessage());
        return ResponseEntity.badRequest().body(errorResponse);
    }

    @ExceptionHandler(LoginFailException.class)
    public ResponseEntity<?> handlerLoginFailException(LoginFailException e) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", false);
        errorResponse.put("message", e.getMessage());
        return ResponseEntity.badRequest().body(errorResponse);
    }
}
