package com.x86s.loginexamples.global;

import com.x86s.loginexamples.domain.member.Member;
import com.x86s.loginexamples.domain.member.MemberRole;
import com.x86s.loginexamples.domain.member.dto.CustomUserDetails;
import com.x86s.loginexamples.jwt.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 스프링 시큐리티 filter chain 요청에 담긴 JWT를 검증하기 위한 커스텀 필터
 * JwtFilter를 통해서 요청 헤더 Authorization에 담긴 키를 검증하고 강제로 SecurityContextHolder에 세션을 생성한다.
 * 생성된 세션은 Stateless 상태이므로 요청이 끝나면 소멸한다.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // request 에서 Authorization 헤더 찾음
        String authorization = request.getHeader("Authorization");

        // Authorization 헤더 검증
        // Authorization 헤더가 비어있거나 "Bearer " 로 시작하지 않을 경우
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.info("[JWT] Token is null...");
            // 토큰이 유효하지 않으므로 request 와 response 를 다음 필터로 넘겨줌
            filterChain.doFilter(request, response);

            return; // 메서드 종료
        }

        // Authorization 에서 Bearer 접두사 제거
        String token = authorization.split(" ")[1];

        // token 소멸시간 검증
        // 유효기간 만료 시
        if (jwtUtil.isExpired(token)) {
            log.info("[JWT] Token is expired...");
            filterChain.doFilter(request, response);

            return;
        }

        // 최종적으로 token 검증 완료 => 일시적인 session 생성
        // session 에 user 정보 설정
        String loginId = jwtUtil.getLoginId(token);
        String role = jwtUtil.getRole(token);


        // 매 요청마다 DB 조회해서 password 초기화할 필요없음 => 정확한 password 를 넣을 필요없음
        // 따라서 임시비밀번호 설정
        Member member = Member.builder()
                .loginId(loginId)
                .password("temp_password_1234!@")
                .role(MemberRole.ADMIN.name().equals(role) ? MemberRole.ADMIN : MemberRole.USER)
                .build();

        // UserDetails 에 회원정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(member);

        // 스프링 시큐리티 인증 토큰 생성
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // 세션에 사용자 등록 => 일시적으로 user 세션 생성
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // 다음 필터로 request, response 넘겨줌
        filterChain.doFilter(request, response);
    }
}
