package com.mdsy.deadendfairytale.util;

import java.security.SecureRandom;

public class SecureUtil {
    /**
     * 자릿수(length) 만큼 랜덤한 숫자 + 문자 조합을 대문자/소문자에 따라 반환 받습니다.
     *
     * @param length      자릿수
     * @param isUpperCase 대문자 여부
     * @return 랜덤한 숫자 + 문자 조합의 문자열
     */
    public static String generateRandomMixStr(int length, boolean isUpperCase) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            sb.append(characters.charAt(index));
        }
        return isUpperCase ? sb.toString() : sb.toString().toLowerCase();
    }
}
