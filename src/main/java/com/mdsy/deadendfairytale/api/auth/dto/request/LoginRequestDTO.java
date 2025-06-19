package com.mdsy.deadendfairytale.api.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class LoginRequestDTO {
    @NotBlank(message = "유저명은 필수값입니다!")
    private String username;
    @NotBlank(message = "비밀번호는 필수값입니다!")
    private String password;

    protected LoginRequestDTO() {}

    public LoginRequestDTO(AuthRequestDTO requestDTO) {
        this.username = requestDTO.getUsername();
        this.password = requestDTO.getPassword();
    }
}
