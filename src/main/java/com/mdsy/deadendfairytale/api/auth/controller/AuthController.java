package com.mdsy.deadendfairytale.api.auth.controller;

import com.mdsy.deadendfairytale.api.auth.dto.request.AuthRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.request.EmailVerificationRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.request.LoginRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.response.AuthResponseDTO;
import com.mdsy.deadendfairytale.api.auth.service.AuthService;
import com.mdsy.deadendfairytale.api.exception.DuplicateUserException;
import com.mdsy.deadendfairytale.api.exception.InfoNotFoundException;
import com.mdsy.deadendfairytale.api.exception.LoginFailException;
import com.mdsy.deadendfairytale.jwt.CustomUserDetails;
import com.mdsy.deadendfairytale.jwt.JwtService;
import com.mdsy.deadendfairytale.util.ValidationUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.angus.mail.iap.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
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

    @Operation(summary = "회원가입 API", description = "회원가입 API 입니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "회원가입 성공",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string",
                                    "username": "string",
                                    "token": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "400", description = "필수값 누락",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
    })
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Validated @RequestBody AuthRequestDTO requestDTO,
                                    BindingResult result) {
        log.info("/api/auth/signup : POST");
        log.info("requestDTO : {}", requestDTO);

        if(result.hasErrors()) {
            return ValidationUtil.handleValidationError(result);
        }

        boolean isSuccess = authService.Signup(requestDTO);

        Map<String, Object> responseDTO = new HashMap<>();
        responseDTO.put("status", isSuccess);
        responseDTO.put("message", "회원가입에 성공했습니다.");

        AuthResponseDTO login = authService.login(new LoginRequestDTO(requestDTO));
        responseDTO.put("username", login.getUsername());
        responseDTO.put("token", login.getToken());


        return ResponseEntity.ok().body(responseDTO);
    }

    @Operation(summary = "로그인 API", description = "로그인 API 입니다")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그인 성공",
                    content = {@Content(schema = @Schema(implementation = AuthResponseDTO.class))}),
            @ApiResponse(responseCode = "400", description = "로그인 실패",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                              """
                              {
                              "status": false,
                              "message": "string"
                              }
                              """))}),
    })
    @PostMapping("/login")
    public ResponseEntity<?> login(@Validated @RequestBody LoginRequestDTO requestDTO,
                                   BindingResult result) {
        log.info("/api/auth/login : POST");
        log.info("requestDTO : {}", requestDTO);

        if(result.hasErrors()) {
            return ValidationUtil.handleValidationError(result);
        }

        AuthResponseDTO responseDTO = authService.login(requestDTO);

        return ResponseEntity.ok().body(responseDTO);
    }

    @Operation(summary = "로그아웃 API",
            description = "로그아웃 API 입니다. \n로그아웃 시 프론트에서도 토큰과 유저정보를 지워줘야 합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그아웃 성공",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": true,
                                    "message": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "400", description = "로그아웃 실패",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "401", description = "로그인 하지 않음",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
    })
    @RequestMapping(value = "/logout", method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<?> logout(@AuthenticationPrincipal CustomUserDetails customUserDetails) {
        log.info("/api/auth/logout : POST");
        log.info("customUserDetails : {}", customUserDetails);

        authService.logout(customUserDetails);

        Map<String, Object> responseDTO = new HashMap<>();
        responseDTO.put("status", true);
        responseDTO.put("message", "로그아웃 되었습니다.");

        return ResponseEntity.ok().body(responseDTO);
    }

    @Operation(summary = "아이디 찾기 API", description = "이메일을 통해 아이디를 찾는 API 입니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "아이디 찾기 성공",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                """
                                {
                                "status": true,
                                "id": "string"
                                }
                                """))),
            @ApiResponse(responseCode = "400", description = "아이디 찾기 실패",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                """
                                {
                                "status": false,
                                "message": "string"
                                }
                                """))),
    })
    @GetMapping("/find-id")
    public ResponseEntity<?> findId(
            @Schema(example = "example@example.com")
            @RequestParam String email) {
        log.info("/api/auth/find-id : POST");
        log.info("email : {}", email);

        String findId = authService.findId(email);

        Map<String, Object> responseDTO = new HashMap<>();
        responseDTO.put("status", true);
        responseDTO.put("id", findId);

        return ResponseEntity.ok().body(responseDTO);
    }

    @Operation(summary = "패스워드 초기화 API", description = "패스워드 초기화 API 입니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "초기화 성공",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": true,
                                    "message": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "400", description = "초기화 실패",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
    })
    @RequestMapping(value = "/reset-password", method = {RequestMethod.PUT, RequestMethod.PATCH})
    public ResponseEntity<?> resetPassword(
            @Schema(example = "example@example.com")
            @RequestParam String email) {
        log.info("/api/auth/find-password : POST");
        log.info("email : {}", email);

        authService.findPassword(email);

        Map<String, Object> responseDTO = new HashMap<>();
        responseDTO.put("status", true);
        responseDTO.put("message", "비밀번호를 초기화 하였습니다. \n이메일에서 변경된 비밀번호를 확인해주세요.");

        return ResponseEntity.ok().body(responseDTO);
    }

    @Operation(summary = "패스워드 변경 API", description = "패스워드 변경 API 입니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "패스워드 변경 성공",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": true,
                                    "message": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "400", description = "패스워드 변경 실패",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "401", description = "로그인 하지 않음",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
    })
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

    @Operation(summary = "토큰 갱신 API", description = "토큰 갱신 API 입니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "토큰 갱신 성공",
                    content = {@Content(schema = @Schema(implementation = AuthResponseDTO.class))}),
            @ApiResponse(responseCode = "400", description = "토큰 갱신 실패",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "401", description = "로그인 하지 않음",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
    })
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

    @Operation(summary = "이메일 인증 API", description = "이메일 인증 API 입니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "이메일 인증 발송 성공",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": true,
                                    "message": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "400", description = "이메일 인증 발송 실패",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
    })
    @PostMapping("/send-email-verification")
    public ResponseEntity<?> sendEmailVerification(
            @Schema(example = "example@example.com")
            @RequestParam String email) {
        log.info("/api/auth/send-email-verification : POST");
        log.info("email: {}", email);
        Map<String, Object> responseDTO = new HashMap<>();

        if (!email.matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
            responseDTO.put("status", false);
            responseDTO.put("message", "이메일 형식이 아닙니다!");
            return ResponseEntity.badRequest().body(responseDTO);
        }

        authService.sendEmailVerification(email);

        responseDTO.put("status", true);
        responseDTO.put("message", "인증 코드가 이메일로 발송되었습니다.");

        return ResponseEntity.ok().body(responseDTO);
    }

    @Operation(summary = "이메일 인증 확인 API", description = "이메일 인증 확인 API 입니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "이메일 인증 성공",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": true,
                                    "message": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "400", description = "이메일 인증 실패",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
            @ApiResponse(responseCode = "403", description = "인증 코드가 올바르지 않거나 인증시간이 만료",
                    content = {@Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example =
                                    """
                                    {
                                    "status": false,
                                    "message": "string"
                                    }
                                    """))}),
    })
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@Validated @RequestBody EmailVerificationRequestDTO requestDTO,
                                         BindingResult result) {
        log.info("/api/auth/verify-email : POST");
        log.info("requestDTO : {}", requestDTO);

        if(result.hasErrors()) {
            return ValidationUtil.handleValidationError(result);
        }

        boolean isVerified = authService.verifyCodeCheck(requestDTO);

        Map<String, Object> responseDTO = new HashMap<>();

        if(isVerified) {
            responseDTO.put("status", true);
            responseDTO.put("message", "이메일 인증이 완료되었습니다.");
            return ResponseEntity.ok().body(responseDTO);
        } else {
            responseDTO.put("status", false);
            responseDTO.put("message", "인증 코드가 올바르지 않거나 인증시간이 만료되었습니다.");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(responseDTO);
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

    @ExceptionHandler(InfoNotFoundException.class)
    public ResponseEntity<?> handlerInfoNotFoundException(InfoNotFoundException e) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", false);
        errorResponse.put("message", e.getMessage());
        return ResponseEntity.badRequest().body(errorResponse);
    }
}
