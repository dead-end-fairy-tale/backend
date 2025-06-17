package com.mdsy.deadendfairytale.api.auth.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@Builder
public class AuthResponseDTO {
    private boolean status;
    private String username;
    private String token;
}
