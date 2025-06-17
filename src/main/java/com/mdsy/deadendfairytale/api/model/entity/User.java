package com.mdsy.deadendfairytale.api.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.Comment;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@ToString
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @Column(nullable = false, unique = true)
    @Comment("회원 아이디")
    private String userId;

    @Column(nullable = false)
    @Comment("회원 비밀번호[암호화됨]")
    private String password;

    @Column(nullable = false)
    @Comment("회원 가입 날짜")
    private LocalDateTime createdAt;

    @Column
    @Comment("로그인한 회원의 리프레시 토큰")
    private String refreshToken;
}
