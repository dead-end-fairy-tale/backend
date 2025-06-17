package com.mdsy.deadendfairytale.filter;

import com.mdsy.deadendfairytale.jwt.CustomUserDetails;
import com.mdsy.deadendfairytale.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);

            try {
                if (JwtUtil.isTokenValid(token)) {
                    String username = JwtUtil.extractUsername(token);

                    // CustomUserDetails 객체 생성
                    CustomUserDetails userDetails = CustomUserDetails.builder()
                            .username(username)
                            .accessToken(token)
                            .build();

                    // 인증 정보 설정
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    
                    log.debug("JWT authentication successful for user: {}", username);
                }
            } catch (Exception e) {
                // 토큰이 유효하지 않은 경우 로그만 남기고 계속 진행
                log.debug("JWT token validation failed: {}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }
}
