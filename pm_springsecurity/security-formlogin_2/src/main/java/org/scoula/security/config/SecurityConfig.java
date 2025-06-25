package org.scoula.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.mybatis.spring.annotation.MapperScan;
import org.scoula.security.filter.AuthenticationErrorFilter;
import org.scoula.security.filter.JwtAuthenticationFilter;
import org.scoula.security.filter.JwtUsernamePasswordAuthenticationFilter;
import org.scoula.security.handler.CustomAccessDeniedHandler;
import org.scoula.security.handler.CustomAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CharacterEncodingFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@Log4j2
@MapperScan(basePackages = {"org.scoula.security.account.mapper"})
@ComponentScan(basePackages = {"org.scoula.security"})
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final AuthenticationErrorFilter authenticationErrorFilter;

    @Autowired
    private JwtAuthenticationFilter authenticationFilter;

    // 커스텀 인증 필터 추가
    @Autowired
    private JwtUsernamePasswordAuthenticationFilter jwtUsernamePasswordAuthenticationFilter;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;


    // 문자셋 필터
    public CharacterEncodingFilter encodingFilter() {
        CharacterEncodingFilter encodingFilter = new CharacterEncodingFilter();
        encodingFilter.setEncoding("UTF-8");
        encodingFilter.setForceEncoding(true);
        return encodingFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .addFilterBefore(encodingFilter(), CsrfFilter.class);
                //token 인증 필터
                .addFilterBefore(jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class)

                //API 로그인 인증 필터 추가
                //로그인 필터
                .addFilterBefore(jwtUsernamePasswordAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class)

                //토큰 인증시 발생하는 예외 처리 필터
                .addFilterBefore(authenticationErrorFilter,
                        JwtAuthenticationFilter.class)

                // 예외 처리 설정
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)  // 401 에러 처리
                .accessDeniedHandler(accessDeniedHandler);           // 403 에러 처리

        //  HTTP 보안 설정
        http.httpBasic().disable()      // 기본 HTTP 인증 비활성화
                .csrf().disable()           // CSRF 보호 비활성화 (REST API에서는 불필요)
                .formLogin().disable()      // 폼 로그인 비활성화 (JSON 기반 API 사용)
                .sessionManagement()        // 세션 관리 설정
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);  // 무상태 모드


        // 경로별, 접근 권한 설정
//        http.authorizeRequests()
//                .antMatchers("/security/all").permitAll() // 모든권한 접근 허용
//                .antMatchers("/security/admin").access("hasRole('ROLE_ADMIN')") // ROLE_ADMIN만 접근 가능
//                .antMatchers("/security/member").access("hasAnyRole('ROLE_ADMIN','ROLE_MEMBER')"); // ROLE_ADMIN, ROLE_MEMBER 접근 가능

        http
                .authorizeRequests() // 경로별 접근 권한 설정
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                .antMatchers("/api/security/all").permitAll()                    // 모두 허용
                .antMatchers("/api/security/member").access("hasRole('ROLE_MEMBER')")  // ROLE_MEMBER 이상
                .antMatchers("/api/security/admin").access("hasRole('ROLE_ADMIN')")    // ROLE_ADMIN 이상
                .anyRequest().authenticated(); // 나머지는 로그인 필요

        http.logout()
                .logoutUrl("/security/logout") // -> Spring Security에서 로그아웃 요청을 받는 POST API
                .invalidateHttpSession(true)
                .deleteCookies("JSESSION-ID")
                .logoutSuccessUrl("/security/logout"); // GET logout 페이지로 전환


        http.rememberMe()
                .key("uniqueAndSecret")                    // 🔑 암호화 키
                .tokenValiditySeconds(86400)               // ⏰ 24시간 유효
                .userDetailsService(userDetailsService);   // 👤 사용자 정보 서비스
    }


    // 직접 만든 userDetailsService를 이용해 인증을 진행하도록 설정
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    // AuthenticationManager
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        // CORS 설정 객체 생성
        CorsConfiguration configuration = new CorsConfiguration();

        // 모든 요청 허용
        configuration.setAllowedOriginPatterns(List.of("*"));
        //  configuration.setAllowedOriginPatterns(Arrays.asList("http://localhost:5173"));

        // 허용할 HTTP 메서드 목록 지정
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));

        // 모든 요청 헤더 허용
        configuration.setAllowedHeaders(List.of("*"));
        // 자격 증명(쿠키, Authorization 헤더 등)을 포함한 요청 허용
        configuration.setAllowCredentials(true);

        // 특정 URL 경로 패턴에 대해 위의 CORS 설정을 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // 모든 경로에 적용

        // 설정된 CORS 소스를 반환 (스프링 시큐리티나 필터 체인에 의해 사용됨)
        return source;
    }

}