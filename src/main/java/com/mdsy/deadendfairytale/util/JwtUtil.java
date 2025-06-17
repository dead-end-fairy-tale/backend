package com.mdsy.deadendfairytale.util;

import com.mdsy.deadendfairytale.properties.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    private static JwtProperties jwtProperties;
    private static Key key;

    @Autowired
    private JwtProperties jwtPropertiesInstance;

    @PostConstruct
    private void init() {
        jwtProperties = this.jwtPropertiesInstance;
        key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Access Token 생성
     */
    public static String generateAccessToken(String username) {
        return generateToken(username, jwtProperties.getAccessTokenExpirationMs());
    }

    /**
     * Refresh Token 생성
     */
    public static String generateRefreshToken(String username) {
        return generateToken(username, jwtProperties.getRefreshTokenExpirationMs());
    }

    /**
     * JWT 토큰 생성
     */
    public static String generateToken(String username, long expirationMs) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * 토큰 유효성 검증
     */
    public static boolean isTokenValid(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            
            return !isTokenExpired(claims);
        } catch (JwtException e) {
            return false;
        }
    }

    /**
     * 토큰에서 사용자명 추출
     */
    public static String extractUsername(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }

    /**
     * 토큰에서 만료일 추출
     */
    public static Date extractExpiration(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getExpiration();
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }

    /**
     * 토큰에서 발급일 추출
     */
    public static Date extractIssuedAt(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getIssuedAt();
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }

    /**
     * 토큰 만료 여부 확인
     */
    public static boolean isTokenExpired(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            
            return isTokenExpired(claims);
        } catch (JwtException e) {
            return true;
        }
    }

    /**
     * Claims에서 토큰 만료 여부 확인
     */
    private static boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    /**
     * 토큰에서 모든 Claims 추출
     */
    public static Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }

    /**
     * 토큰 만료까지 남은 시간 (밀리초)
     */
    public static long getTimeUntilExpiration(String token) {
        Date expiration = extractExpiration(token);
        return expiration.getTime() - System.currentTimeMillis();
    }

    /**
     * Access Token 만료 시간 조회
     */
    public static long getAccessTokenExpirationMs() {
        return jwtProperties.getAccessTokenExpirationMs();
    }

    /**
     * Refresh Token 만료 시간 조회
     */
    public static long getRefreshTokenExpirationMs() {
        return jwtProperties.getRefreshTokenExpirationMs();
    }
}
