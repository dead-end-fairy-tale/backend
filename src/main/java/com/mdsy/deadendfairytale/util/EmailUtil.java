package com.mdsy.deadendfairytale.util;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.util.Random;

public class EmailUtil {

    public static String generateVerificationCode() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1000000));
    }

    public static void sendEmail(JavaMailSender mailSender, String email, String verificationCode) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("막장동화 이메일 인증 코드");
        message.setText(
                "막장동화 회원가입을 위한 이메일 인증 코드입니다.\n\n" +
                        "인증 코드: " + verificationCode + "\n\n" +
                        "이 코드는 5분간 유효합니다."
        );

        mailSender.send(message);
    }
}
