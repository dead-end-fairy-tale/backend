package com.mdsy.deadendfairytale.api.auth.controller;

import com.mdsy.deadendfairytale.api.auth.dto.request.AuthRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.request.EmailVerificationRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.request.LoginRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.response.AuthResponseDTO;
import com.mdsy.deadendfairytale.api.auth.service.AuthService;
import com.mdsy.deadendfairytale.api.exception.DuplicateUserException;
import com.mdsy.deadendfairytale.api.exception.LoginFailException;
import com.mdsy.deadendfairytale.jwt.CustomUserDetails;
import com.mdsy.deadendfairytale.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
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

        AuthResponseDTO login = authService.login(new LoginRequestDTO(requestDTO));
        responseDTO.put("username", login.getUsername());
        responseDTO.put("token", login.getToken());


        return ResponseEntity.ok().body(responseDTO);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO requestDTO) {
        log.info("/api/auth/login : POST");
        log.info("requestDTO : {}", requestDTO);

        AuthResponseDTO responseDTO = authService.login(requestDTO);

        return ResponseEntity.ok().body(responseDTO);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String email) {
        log.info("/api/auth/find-password : POST");
        log.info("email : {}", email);

        authService.findPassword(email);

        Map<String, Object> responseDTO = new HashMap<>();
        responseDTO.put("status", true);
        responseDTO.put("message", "비밀번호를 초기화 하였습니다. \n이메일에서 변경된 비밀번호를 확인해주세요.");

        return ResponseEntity.ok().body(responseDTO);
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@AuthenticationPrincipal CustomUserDetails userDetails,
                                            @RequestParam String password) {
        log.info("/api/auth/change-password : POST");
        log.info("password : {}", password);

        authService.changePassword(userDetails, password);

        Map<String, Object> responseDTO = new HashMap<>();
        responseDTO.put("status", true);
        responseDTO.put("message", "비밀번호를 변경하였습니다.");

        return ResponseEntity.ok().body(responseDTO);
    }

//    @GetMapping("/logout")
//    public ResponseEntity<?> logout(@AuthenticationPrincipal CustomUserDetails customUserDetails) {
//        log.info("/api/auth/logout : POST");
//        log.info("customUserDetails : {}", customUserDetails);
//
//        authService.logout(customUserDetails);
//    }

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

    @PostMapping("/send-email-verification")
    public ResponseEntity<?> sendEmailVerification(@RequestParam String email, HttpServletRequest request) {
        log.info("/api/auth/send-email-verification : POST");
        log.info("email: {}", email);

        authService.sendEmailVerification(email);

        Map<String, Object> responseDTO = new HashMap<>();
        responseDTO.put("status", true);
        responseDTO.put("message", "인증 코드가 이메일로 발송되었습니다.");

        return ResponseEntity.ok().body(responseDTO);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestBody EmailVerificationRequestDTO requestDTO, HttpServletRequest request) {
        log.info("/api/auth/verify-email : POST");
        log.info("requestDTO : {}", requestDTO);

        boolean isVerified = authService.verifyCodeCheck(requestDTO);

        Map<String, Object> responseDTO = new HashMap<>();

        if(isVerified) {
            responseDTO.put("status", true);
            responseDTO.put("message", "이메일 인증이 완료되었습니다.");
            return ResponseEntity.ok().body(responseDTO);
        } else {
            responseDTO.put("status", false);
            responseDTO.put("message", "인증 코드가 올바르지 않거나 인증시간이 만료되었습니다.");
            return ResponseEntity.ok().body(responseDTO);
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
