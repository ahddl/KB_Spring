package org.scoula.security.filter;


import lombok.extern.log4j.Log4j2;
import org.scoula.security.account.dto.LoginDTO;
import org.scoula.security.handler.LoginFailureHandler;
import org.scoula.security.handler.LoginSuccessHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Log4j2
@Component
public class JwtUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
//스프링 생성자 주입을 통해 전달
    public JwtUsernamePasswordAuthenticationFilter(
            AuthenticationManager authenticationManager, // SecurityConfig가 생성된 이후에 등록됨
            LoginSuccessHandler loginSuccessHandler,
            LoginFailureHandler loginFailureHandler) {
        super(authenticationManager);
        setFilterProcessesUrl("/api/auth/login"); // POST 로그인 요청 url, 필터 적용 주소
        setAuthenticationSuccessHandler(loginSuccessHandler); //로그인 성공 핸들러 등록
        setAuthenticationFailureHandler(loginFailureHandler); //로그인 실패 핸들러 등록
    }

    // 로그인 요청  URL 인 경우 로그인 작업 처리
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

                    /*
            1. http bodey에 들어온 json -> dto(LoginDTO.of())
            인증해달라고 인증 매니저에 요청
            2. 인증 매니저에게 로그인 정보를 줄 때 는 Token객체를 만들어서 주어야함
            인증 정보 token 만들기(<-dto)
            3. 인증매니저에게 토큰을 주면서 인증해줘라고 요청
            -->  성공하면 Authencation 객체를 생성해서 리턴해줌
             */
// 요청 BODY의 JSON에서 username, password  LoginDTO
        LoginDTO login = LoginDTO.of(request);

//인증토큰 (UsernamePasswordAuthenticationToken) 구성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword());

// AuthenticationManager에게 인증 요청
        return getAuthenticationManager().authenticate(authenticationToken);
    }

}