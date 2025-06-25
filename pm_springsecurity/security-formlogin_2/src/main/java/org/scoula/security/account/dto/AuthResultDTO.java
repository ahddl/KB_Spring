package org.scoula.security.account.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

//로그인 성공 결과를 나타내는 최종 응답 DTO
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResultDTO {
    private String token;        // JWT 인증 토큰
    private UserInfoDTO user;    // 사용자 기본 정보
}