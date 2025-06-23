package org.scoula.security.account.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MemberVO {

    private String username;
    private String password;
    private String email;
    private String regDate;
    private String updateDate;

    private List<AuthVO> authList;
}
