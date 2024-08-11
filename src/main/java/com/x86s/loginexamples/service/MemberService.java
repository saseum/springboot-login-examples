package com.x86s.loginexamples.service;

import com.x86s.loginexamples.domain.member.Member;
import com.x86s.loginexamples.domain.member.dto.JoinRequest;
import com.x86s.loginexamples.domain.member.dto.LoginRequest;
import com.x86s.loginexamples.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@RequiredArgsConstructor
//@Transactional
@Service
public class MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public boolean checkLoginIdDuplicate(String loginId) {
        return memberRepository.existsByLoginId(loginId);
    }

    public void join(JoinRequest joinRequest) {
        memberRepository.save(joinRequest.toEntity());
    }

    public Member login(LoginRequest loginRequest) {
        Member findMember = memberRepository.findByLoginId(loginRequest.getLoginId());

        if(findMember == null) {
            return null;
        }

        if(!findMember.getPassword().equals(loginRequest.getPassword())) {
            return null;
        }

        return findMember;
    }

    public Member getLoginMemberById(Long memberId) {
        if(memberId == null) return null;

        Optional<Member> findMember = memberRepository.findById(memberId);
        return findMember.orElse(null);
    }

    // BCryptPasswordEncoder를 통해서 비밀번호 암호화 작업 추가한 회원가입 로직
    public void securityJoin(JoinRequest joinRequest) {
        if (memberRepository.existsByLoginId(joinRequest.getLoginId())) {
            return;
        }

        joinRequest.setPassword(bCryptPasswordEncoder.encode(joinRequest.getPassword()));

        Member saveMember = memberRepository.save(joinRequest.toEntity());
    }

    public Member getLoginMemberByLoginId(String loginId) {
        return memberRepository.findByLoginId(loginId);
    }
}
