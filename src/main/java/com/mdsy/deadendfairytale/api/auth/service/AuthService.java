package com.mdsy.deadendfairytale.api.auth.service;

import com.mdsy.deadendfairytale.api.auth.dto.request.AuthRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.request.EmailVerificationRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.request.LoginRequestDTO;
import com.mdsy.deadendfairytale.api.auth.dto.response.AuthResponseDTO;
import com.mdsy.deadendfairytale.api.exception.DuplicateUserException;
import com.mdsy.deadendfairytale.api.exception.InfoNotFoundException;
import com.mdsy.deadendfairytale.api.exception.LoginFailException;
import com.mdsy.deadendfairytale.api.model.entity.EmailVerification;
import com.mdsy.deadendfairytale.api.model.entity.User;
import com.mdsy.deadendfairytale.api.repository.EmailVerificationRepository;
import com.mdsy.deadendfairytale.api.repository.UserRepository;
import com.mdsy.deadendfairytale.util.EmailUtil;
import com.mdsy.deadendfairytale.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final EmailVerificationRepository emailVerificationRepository;
    private final JavaMailSender mailSender;

    @Transactional
    public boolean Signup(AuthRequestDTO requestDTO) {
        if(userRepository.existsById(requestDTO.getUsername())) {
            throw new DuplicateUserException("이미 가입된 유저명입니다.");
        }

        if(userRepository.existsByEmail(requestDTO.getEmail())) {
            throw new DuplicateUserException("이미 가입된 이메일입니다.");
        }

        if(emailVerificationRepository.findByEmailAndVerified(requestDTO.getEmail(), true).isEmpty()) {
            throw new InfoNotFoundException("이메일 인증이 완료되지 않았습니다!");
        }

        User user = User.builder()
                .userId(requestDTO.getUsername())
                .password(passwordEncoder.encode(requestDTO.getPassword()))
                .email(requestDTO.getEmail())
                .createdAt(LocalDateTime.now())
                .build();

        userRepository.save(user);

        return true;
    }

    @Transactional
    public AuthResponseDTO login(LoginRequestDTO requestDTO) {
        Optional<User> findUser = userRepository.findById(requestDTO.getUsername());

        if(findUser.isPresent()) {
            User user = findUser.get();
            if(!passwordEncoder.matches(requestDTO.getPassword(), user.getPassword())) {
                throw new LoginFailException("아이디 혹은 비밀번호가 일치하지 않습니다!");
            }

            String accessToken = JwtUtil.generateAccessToken(user.getUserId());
            String refreshToken = JwtUtil.generateRefreshToken(user.getUserId());

            user.setRefreshToken(refreshToken);
            userRepository.save(user);

            return AuthResponseDTO.builder()
                    .status(true)
                    .username(user.getUserId())
                    .token(accessToken)
                    .build();
        } else {
            throw new LoginFailException("아이디 혹은 비밀번호가 일치하지 않습니다!");
        }
    }

    public AuthResponseDTO refreshTokenByAccessToken(String expiredAccessToken) {
        try {
            // 1. 만료된 accessToken에서 사용자명 추출 (만료되어도 페이로드는 읽을 수 있음)
            String username = JwtUtil.extractUsername(expiredAccessToken);
            
            // 2. DB에서 사용자 조회
            User findUser = userRepository.findById(username).orElseThrow(
                    () -> new LoginFailException("사용자를 찾을 수 없습니다.")
            );

            // 3. DB에 저장된 refreshToken 확인
            if (findUser.getRefreshToken() == null || findUser.getRefreshToken().trim().isEmpty()) {
                throw new LoginFailException("저장된 리프레시 토큰이 없습니다.");
            }

            // 4. refreshToken 유효성 검증
            if (!JwtUtil.isTokenValid(findUser.getRefreshToken())) {
                throw new LoginFailException("리프레시 토큰이 만료되었습니다. \n다시 로그인해 주세요.");
            }

            // 5. 새로운 accessToken 생성
            String newAccessToken = JwtUtil.generateAccessToken(username);

            // 6. 응답 반환
            return AuthResponseDTO.builder()
                    .status(true)
                    .username(username)
                    .token(newAccessToken)
                    .build();

        } catch (Exception e) {
            throw new LoginFailException("토큰 갱신에 실패했습니다: " + e.getMessage());
        }
    }

    @Transactional
    public void sendEmailVerification(String email) {
        boolean isEmailDuplicate = userRepository.existsByEmail(email);

        if(isEmailDuplicate) {
            throw new DuplicateUserException("이미 가입된 이메일입니다.");
        }

        String verificationCode = EmailUtil.generateVerificationCode();

        emailVerificationRepository.deleteById(email);

        EmailVerification emailVerification = EmailVerification.builder()
                .email(email)
                .verificationCode(verificationCode)
                .expirationDate(LocalDateTime.now().plusMinutes(5))
                .verified(false)
                .build();

        emailVerificationRepository.save(emailVerification);

        EmailUtil.sendEmail(mailSender, email, verificationCode);
    }

    public boolean verifyCodeCheck(EmailVerificationRequestDTO requestDTO) {
        return emailVerificationRepository.findByEmail(
                requestDTO.getEmail()
        )
                .map(verification -> {
                    if(verification.getVerificationCode().equals(requestDTO.getCode())) {
                        if (verification.getExpirationDate().isAfter(LocalDateTime.now())) {
                            verification.setVerified(true);
                            emailVerificationRepository.save(verification);
                            return true;
                        }
                    }
                    return false;
                }).orElseThrow(
                        () -> new InfoNotFoundException("먼저 이메일 인증을 신청해주세요!")
                );

    }
}
