package org.scoula.security.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.scoula.config.RootConfig;
import org.scoula.security.config.SecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {RootConfig.class, SecurityConfig.class})
@Log4j2
class JwtProcessorTest {

    @Autowired
    JwtProcessor jwtProcessor;

    @Test
    void generateToken() {
        String username = "user0";
        String token = jwtProcessor.generateTokenByLogin(username);
        log.info(token);
        assertNotNull(token);
    }

    @Test
    void getUsername() {
        String token = "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJ1c2VyMCIsImlhdCI6MTcyMTgwMjc4NCwiZXhwIjoxNzIxODAzMDg0fQ.nwD4rIr oYL6hr_ - Esav8KIsHw573MbAiTT - Nz_yYHI8bMcyGZMOEjMt0Own3io_c ";
        String username = jwtProcessor.getUsername(token);
        log.info(username);
        assertNotNull(username);
    }


    @Test
    void testGenerateToken() {
    }

    @Test
    void validateToken() {

        //잇앟나 토큰 (잘못된 형식)
        String token = "invalid.jwt.token";

        //토큰 검증
        boolean valid = jwtProcessor.validateToken(token);

        log.info("검증 결과 : {} " + valid);
    }
}