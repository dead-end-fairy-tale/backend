package com.mdsy.deadendfairytale.jwt;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Getter
@Builder
public class CustomUserDetails implements UserDetails {
    private String username;
    private String password;
    private String accessToken;
    private String refreshToken;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 기본적으로 빈 권한 목록 반환 (필요시 Role 기반으로 권한 설정)
        return Collections.emptyList();
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
