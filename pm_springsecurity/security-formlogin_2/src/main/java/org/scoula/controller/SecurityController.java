package org.scoula.controller;


//○ all, member, admin 뷰 jsp 작성

import lombok.extern.log4j.Log4j2;
import org.scoula.security.account.domain.CustomUser;
import org.scoula.security.account.domain.MemberVO;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

//@Controller
//@RequestMapping("/security")
@RequestMapping("/api/security")
@RestController
@Log4j2
public class SecurityController {

    /*
    @GetMapping("/all")
    public void doAll() {
//        접속시 로그 출력 및 sercurity / all 뷰로 이동
        log.info("비회원, 회원, 관리자 모두 접근 가능 페이지");
    }

    @GetMapping("/member")
    public void doMember() {
//        접속시 로그 출력 및 sercurity / member 뷰로 이동
        log.info("회원과 관리자만 모두 접근 가능 페이지");
    }

    @GetMapping("/admin")
    public void doAdmin() {
//        접속시 로그 출력 및 sercurity / admin 뷰로 이동
        log.info("관리자만 접근 가능 페이지");
    }
     */

    /**
     * 모든 사용자 접근 가능 (인증 불필요)
     */
    @GetMapping("/all")
    public ResponseEntity<String> doAll() {
        log.info("do all can access everybody");
        return ResponseEntity.ok("All can access everybody");
    }

    /**
     * ROLE_MEMBER 권한 필요
     */
    @GetMapping("/member")
    public ResponseEntity<String> doMember(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        log.info("username = " + userDetails.getUsername());
        return ResponseEntity.ok(userDetails.getUsername());
    }

    /**
     * ROLE_ADMIN 권한 필요
     */
    @GetMapping("/admin")
    public ResponseEntity<MemberVO> doAdmin(
            @AuthenticationPrincipal CustomUser customUser
    ) {
        MemberVO member = customUser.getMember();
        log.info("username = " + member);
        return ResponseEntity.ok(member);
    }

    @GetMapping("/login")
    public void doLogin() {
        log.info("로그인 페이지로 전환");
    }

    @GetMapping("/logout")
    public void doLogout() {
        log.info("로그아웃 페이지로 전환");
    }


    /*
     * ○ Principal 주입
     * ○ Authentication 주입
     * ○ @AuthenticationPrincipal 주입
     * */

    // Principal
    // 가장 단순한 방식 -> 로그인한 사용자의 username만 필요할 때 사용
    @GetMapping("/member/principal")
    public void printUserDetailByPrincipal(Principal principal) {
        log.info("username ======> {}", principal.getName());
    }

    // Authentication
    // 사용자 이름뿐 아니라, 권한, 인증상태, 자격 증명 등 접근 가능
    @GetMapping("/member/authentication")
    public void printUserDetailByAuthentication(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        log.info("username =======> {}", userDetails.getUsername());
    }

    // @AuthenticationPrincipal
    // SpirngSecurity가 authentication.getPrincipal()에서 꺼낸 객체를 직접 주입
    // -> CustomUserDetails (구현체)에 접근 가능 (CustomUser)
    @GetMapping("/member/authentication-principal")
    public void printUserDetailByAuthenticationPrincipal(
            @AuthenticationPrincipal CustomUser customUser) {
        MemberVO memberVO = customUser.getMember();
        log.info("memberVO ======> {}", memberVO);
    }

}
