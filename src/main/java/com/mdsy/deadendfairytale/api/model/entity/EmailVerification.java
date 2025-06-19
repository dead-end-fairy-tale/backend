package com.mdsy.deadendfairytale.api.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.Comment;

import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder

@Table(name = "email_verifications")
@Entity
public class EmailVerification {
    @Id
    @Comment("이메일 인증을 받은 이메일")
    private String email;

    @Column(nullable = false)
    @Comment("이메일 인증 코드")
    private String verificationCode;

    @Column(nullable = false)
    @Comment("이메일 인증 기한")
    private LocalDateTime expirationDate;

    @Column(nullable = false)
    @Comment("이메일 인증 여부")
    private boolean verified;
}
