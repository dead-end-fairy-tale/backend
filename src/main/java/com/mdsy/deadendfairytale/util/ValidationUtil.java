package com.mdsy.deadendfairytale.util;


import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


public class ValidationUtil {

    /**
     * Validation 에러 발생 시 공통 응답을 만들어주는 메서드
     * @param result 발생한 Validation
     * @return 발생한 Validation 중 첫 번째 에러 메세지만 리턴
     */
    public static ResponseEntity<?> handleValidationError(BindingResult result) {
        String validationMessage = preparedValidationMessage(result);
        Map<String, Object> response = new HashMap<>();
        response.put("status", false);
        response.put("message", validationMessage);

        return ResponseEntity.badRequest().body(response);
    }

    /***
     * Validation 입력값에 걸려서 온 BindingResult안에 담긴 에러메세지만 가공해서 리턴하는 메서드
     * @param result : Validation 인증값에 걸려서 발생한 에러 메세지가 담긴 BindingResult
     * @return : 인증값 검증에 걸린 각 메세지들을 줄바꿈 해서 String으로 반환
     */
    public static String preparedValidationMessage(BindingResult result) {
        List<String> errorMessageList = result.getAllErrors().stream()
                .map(ObjectError::getDefaultMessage)
                .collect(Collectors.toList());

        return String.join("\n", errorMessageList);
    }
}
