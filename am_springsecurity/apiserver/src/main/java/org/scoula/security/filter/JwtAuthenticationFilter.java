package org.scoula.security.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.scoula.security.util.JwtProcessor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Component
@Log4j2
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer "; //

    private final JwtProcessor jwtProcessor;
    private final UserDetailsService userDetailsService;

    private Authentication getAuthentication(String token) {
        String username = jwtProcessor.getUsername(token);
        UserDetails princiapl = userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(princiapl, null, princiapl.getAuthorities());
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
 log.info("💌💌💌💌💌💌💌doFilterInternal");
            // 1. 헤더에서 Authorization 붙어 있는 걸을 추출하세요
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        // 2. 앞에서 추출한 값이 있는지, bearer로 시작하는지 체크하세요
        // -> bearer 뒤에 있는 jwt 토큰 값을 추출합니다
        if (bearerToken != null && bearerToken.startsWith(BEARER_PREFIX)) {
            String token = bearerToken.substring(BEARER_PREFIX.length());

            // 3. token에서 uesrname 추출한 후,db 검색을 해서 회원정보를 구체적으로 가지고 오자
            // db로부터 잘 가지고 왔으면 Authorization 객체 만들어서
            // ==> getAuthentication()
// Authentication SecurityContext
            Authentication authentication = getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // 4. SecurityContextHolder에 넣어두면 어디서든 꺼내서 인증 정보를 쓸 수 있음

        super.doFilter(request, response, filterChain);
    }
}