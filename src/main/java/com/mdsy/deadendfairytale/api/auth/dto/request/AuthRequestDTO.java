package com.mdsy.deadendfairytale.api.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class AuthRequestDTO {
    @NotBlank(message = "유저명은 필수값입니다!")
    private String username;
    @NotBlank(message = "비밀번호는 필수값입니다!")
    private String password;
    @Email(message = "이메일 형식이 아닙니다!")
    @NotBlank(message = "이메일은 필수값입니다!")
    @Schema(example = "example@example.com")
    private String email;
}
