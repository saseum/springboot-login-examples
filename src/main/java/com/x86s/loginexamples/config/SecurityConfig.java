package com.x86s.loginexamples.config;

import com.x86s.loginexamples.global.JwtFilter;
import com.x86s.loginexamples.global.LoginFilter;
import com.x86s.loginexamples.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final AuthenticationConfiguration configuration;
    private final JwtUtil jwtUtil;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 스프링 시큐리티 jwt 로그인 설정
        http
                // 프레임 옵션 비활성화(H2 콘솔 접근을 위해)
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.disable()))
                // csrf disable 설정
                .csrf(auth -> auth.disable())
                // 폼로그인 형식 disable 설정 => Postman으로 검증
                .formLogin(auth -> auth.disable())
                // http basic 인증방식 disable 설정
                .httpBasic(auth -> auth.disable())
                // 경로별 인가 작업
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/jwt-login", "/jwt-login/", "/jwt-login/login", "/jwt-login/join", "/h2-console/**").permitAll()
                        .requestMatchers("/jwt-login/admin").hasRole("ADMIN")
                        .anyRequest().authenticated())
                // 세션 설정
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 커스텀 로그인 필터를 원래의 (UsernamePasswordAuthenticationFilter) 위치에 넣음
                .addFilterAt(new LoginFilter(authenticationManager(configuration), jwtUtil), UsernamePasswordAuthenticationFilter.class)
                // 로그인 필터 이전에 JwtFilter 넣음
                .addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class);

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
