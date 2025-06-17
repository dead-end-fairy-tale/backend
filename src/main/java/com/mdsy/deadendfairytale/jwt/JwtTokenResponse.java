package com.mdsy.deadendfairytale.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtTokenResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private long expiresIn; // Access Token 만료까지 남은 시간 (초)
    
    public static JwtTokenResponse of(String accessToken, String refreshToken, long expiresIn) {
        return JwtTokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .build();
    }
}
