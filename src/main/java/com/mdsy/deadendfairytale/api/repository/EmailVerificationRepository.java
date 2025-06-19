package com.mdsy.deadendfairytale.api.repository;

import com.mdsy.deadendfairytale.api.model.entity.EmailVerification;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EmailVerificationRepository extends JpaRepository<EmailVerification, String> {
    Optional<EmailVerification> findByEmailAndVerificationCode(String email, String verificationCode);

    Optional<EmailVerification> findByEmailAndVerified(String email, boolean verified);

    Optional<EmailVerification> findByEmail(String email);
}
