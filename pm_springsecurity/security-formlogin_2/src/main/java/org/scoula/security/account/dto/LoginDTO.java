package org.scoula.security.account.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;

import javax.servlet.http.HttpServletRequest;

@Data
@NoArgsConstructor
@AllArgsConstructor
/*
- Spring Security 규약에 따라 `username`과 `password` 프로퍼티를 가짐
- JSON 역직렬화를 위해 `Jackson data-bind` 라이브러리 사용
(Request body의 JSON 문자열을 LoginDTO 객체로 직접 역직렬화 수행)
 */
public class LoginDTO {
    private String username;
    private String password;

    /**
     * HTTP 요청에서 JSON을 LoginDTO 객체로 변환
     *
     * @param request
     * @return LoginDTO로 변환된 요청 데이터
     */
    public static LoginDTO of(HttpServletRequest request) {
        ObjectMapper om = new ObjectMapper();
        try {

            // RequestBody에 담긴 JSON 문자열을 읽어와 LoginDTO로 역직렬화
            return om.readValue(request.getInputStream(), LoginDTO.class);
        } catch (Exception e) {
            e.printStackTrace();
            throw new BadCredentialsException("username 또는 password가 없습니다.");
        }
    }
}
