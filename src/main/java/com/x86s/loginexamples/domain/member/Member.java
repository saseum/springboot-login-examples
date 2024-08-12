package com.x86s.loginexamples.domain.member;

import jakarta.persistence.*;
import lombok.*;

@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Member {

    @Column(name="member_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    private String loginId;
    private String password;
    private String name;

    private MemberRole role;
}
