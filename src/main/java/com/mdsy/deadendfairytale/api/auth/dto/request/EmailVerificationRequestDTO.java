package com.mdsy.deadendfairytale.api.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class EmailVerificationRequestDTO {
    @NotBlank(message = "이메일은 필수입니다!")
    private String email;
    @NotBlank(message = "인증코드는 필수입니다!")
    private String code;
}
