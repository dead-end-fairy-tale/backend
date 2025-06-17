package com.mdsy.deadendfairytale.api.auth.dto.request;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class AuthRequestDTO {
    private String username;
    private String password;
}
