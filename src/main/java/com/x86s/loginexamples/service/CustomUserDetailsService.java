package com.x86s.loginexamples.service;

import com.x86s.loginexamples.domain.member.Member;
import com.x86s.loginexamples.domain.member.dto.CustomUserDetails;
import com.x86s.loginexamples.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByLoginId(username);

        if (!Objects.isNull(member)) {
            return new CustomUserDetails(member);
        }
        return null;
    }
}
