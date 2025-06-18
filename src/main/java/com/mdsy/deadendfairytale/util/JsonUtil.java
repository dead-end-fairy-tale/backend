package com.mdsy.deadendfairytale.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;

public class JsonUtil {
    public static void responseJson(Object dto, HttpServletResponse response) {
        try {
            //JSON 형태의 응답 생성
            ObjectMapper objectMapper = new ObjectMapper();
            String json = objectMapper.writeValueAsString(dto);

            //응답 설정
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(json);
            response.getWriter().flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    // 맨 처음에 있는 정보가 BOM일 경우 지워주는 메서드
    public static String removeBOM(String str) {
        if(str.startsWith("\uFEFF"))
            str = str.substring(1);

        return str;
    }
}
