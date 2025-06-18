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
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static com.mdsy.deadendfairytale.util.JsonUtil.responseJson;

@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        String requestURI = request.getRequestURI();
        boolean isApiRequest = requestURI.startsWith("/api");

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
                    
                    log.debug("토큰 인증에 성공했습니다! user: {}", username);
                }
            } catch (Exception e) {
                // 토큰이 유효하지 않은 경우
                log.debug("토큰이 유효하지 않습니다!: {}", e.getMessage());
                if(isApiRequest)
                    setUnauthorizedResponse(response, "토큰이 유효하지 않습니다!");
            }
        }

        filterChain.doFilter(request, response);
    }

    void setUnauthorizedResponse(HttpServletResponse response, String message) {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("status", false);
        responseMap.put("message", message);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        responseJson(responseMap, response);
    }
}
