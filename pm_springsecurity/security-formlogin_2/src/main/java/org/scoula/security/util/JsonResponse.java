package org.scoula.security.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

//spring Security 필터나 예외 핸들러에서 Json 응답을 일관되게 보내기 위해 사용하는 유틸
//로그인 결과를 필터에서 직접 JSON으로 직렬화하여 HTTP 응답으로 직접 전송 위한 유틸리티 클래스
public class JsonResponse {
    // 제네릭을 사용한 JSON 응답 처리
    public static <T> void send(HttpServletResponse response, T result) throws IOException {
        ObjectMapper om = new ObjectMapper();
        response.setContentType("application/json;charset=UTF-8");
        Writer out = response.getWriter();
        out.write(om.writeValueAsString(result));  // 객체를 JSON 문자열로 직렬화
        out.flush();
    }

    // 에러 응답 처리
    public static void sendError(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType("application/json;charset=UTF-8");
        Writer out = response.getWriter();
        out.write(message);
        out.flush();
    }
}