package com.mdsy.deadendfairytale.jwt;

import com.mdsy.deadendfairytale.util.JwtUtil;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    /**
     * 사용자명으로 JWT 토큰 쌍 생성
     */
    public JwtTokenResponse generateTokens(String username) {
        String accessToken = JwtUtil.generateAccessToken(username);
        String refreshToken = JwtUtil.generateRefreshToken(username);

        // Access Token 만료 시간 (초 단위)
        long expiresIn = JwtUtil.getAccessTokenExpirationMs() / 1000;

        return JwtTokenResponse.of(accessToken, refreshToken, expiresIn);
    }

    /**
     * Refresh Token으로 새로운 Access Token 생성
     */
    public JwtTokenResponse refreshAccessToken(String refreshToken) {
        if (!JwtUtil.isTokenValid(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        String username = JwtUtil.extractUsername(refreshToken);
        String newAccessToken = JwtUtil.generateAccessToken(username);

        // Access Token 만료 시간 (초 단위)
        long expiresIn = JwtUtil.getAccessTokenExpirationMs() / 1000;

        return JwtTokenResponse.of(newAccessToken, refreshToken, expiresIn);
    }

    /**
     * 토큰 유효성 검증
     */
    public boolean validateToken(String token) {
        return JwtUtil.isTokenValid(token);
    }

    /**
     * 토큰에서 사용자명 추출
     */
    public String extractUsername(String token) {
        return JwtUtil.extractUsername(token);
    }

    /**
     * 토큰 만료 여부 확인
     */
    public boolean isTokenExpired(String token) {
        return JwtUtil.isTokenExpired(token);
    }

    /**
     * 토큰 만료까지 남은 시간 반환 (초 단위)
     */
    public long getTimeUntilExpirationInSeconds(String token) {
        return JwtUtil.getTimeUntilExpiration(token) / 1000;
    }
}