package org.scoula.controller;

/*
    ○ /security/all : 모두 접근 가능
    ○ /security/member: ROLE_MEMBER 권한인 경우 접근 가능
    ○ /security/admin: ROLE_ADMIN, ROLE_MEMBER 권한인 경우 접근 가능
 */
import lombok.extern.log4j.Log4j2;
import org.scoula.security.account.domain.CustomUser;
import org.scoula.security.account.domain.MemberVO;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
@RequestMapping("/security")
@Log4j2
public class SecurityController {
    @GetMapping("/all")
    public void doAll(){
        //접속시 로그 출력 및 sercurity / all 뷰로 이동
        log.info("비회원, 회원, 관리자 모두 접근 가능");
    }

    @GetMapping("/member")
    public void doMember(){
        log.info("회원 접근 가능");
    }

    @GetMapping("/admin")
    public void doAdmin(){
        log.info("관리자 접근 가능");
    }

    @GetMapping("/login")
    public void doLogin(){
        log.info("로그인 페이지로 전환");
    }

    @GetMapping("/logout")
    public void doLogout(){
        log.info("로그아웃 페이지로 전환");
    }
    /*
    Principal 주입
    Authentication 주입
    @AuthenticationPrincipal 주입
     */

    //Principal 주입
    //가장 단순한 방식 -> 로그인한 사용자의 username만 필요할 때 사용
    @GetMapping("/member/principal")
    public void printUserDetailByPrincipal(Principal principal){
        log.info("username =====> {}", principal.getName());
    }

    // Authentication 주입
    //사용자 이름 뿐 아니라, 권한, 인증상태, 자격 증명 등 접근 가능
    @GetMapping("/member/authentication")
    public void printUserDetailByAuthentication(Authentication authentication){
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        log.info("username =====> {}", userDetails.getUsername());
    }

    //@AuthenticationPrincipal 주입
    //SpringSecurity가 authentication.getPrincipal()에서 꺼낸 객체를 직접 주입
    // -> CustomUserDatails (구현체) 에 접근 가능 (CustomUser)
    @GetMapping("/member/authentication-principal")
    public void printUserDetailByAuthenticationPrincipal(@AuthenticationPrincipal CustomUser customUser){
        MemberVO memberVO = customUser.getMember();
        log.info("username =====> {}", memberVO.getUsername());
    }

}
