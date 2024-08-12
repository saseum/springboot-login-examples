package com.x86s.loginexamples.global;

import com.x86s.loginexamples.domain.member.dto.CustomUserDetails;
import com.x86s.loginexamples.jwt.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String loginId = obtainUsername(request);
        String password = obtainPassword(request);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(loginId, password, null);
        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // username 추출
        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
        String username = customUserDetails.getUsername();

        // role 추출
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> it = authorities.iterator();
        GrantedAuthority auth = it.next();
        String role = auth.getAuthority();

        // JwtUtil에 token 생성 요청
        String token = jwtUtil.createJwt(username, role, 60 * 60 * 1000L);

        // JWT를 response에 담아 응답(header 부분)
        // key: "Authorization"
        // value: "Bearer " (인증방식) + token
        response.addHeader("Authorization", "Bearer " + token);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        // 실패 시 401 응답코드
        response.setStatus(401);
    }
}
