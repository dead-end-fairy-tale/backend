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
public class EmailVerificationRequestDTO {
    @Email(message = "이메일 형식이 아닙니다!")
    @NotBlank(message = "이메일은 필수입니다!")
    @Schema(example = "example@example.com")
    private String email;
    @NotBlank(message = "인증코드는 필수입니다!")
    private String code;
}
