package com.mdsy.deadendfairytale.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secret;
    private AccessToken accessToken = new AccessToken();
    private RefreshToken refreshToken = new RefreshToken();

    @Getter
    @Setter
    public static class AccessToken {
        private long expirationMs;
    }

    @Getter
    @Setter
    public static class RefreshToken {
        private long expirationMs;
    }

    public long getAccessTokenExpirationMs() {
        return accessToken.getExpirationMs();
    }

    public long getRefreshTokenExpirationMs() {
        return refreshToken.getExpirationMs();
    }
}
