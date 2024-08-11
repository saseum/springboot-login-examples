package com.x86s.loginexamples.config;

import com.x86s.loginexamples.domain.member.MemberRole;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 인가 동작 순서
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/security-login", "/security-login/login", "/security-login/join", "/h2-console/**").permitAll()
                        .requestMatchers("/security-login/admin").hasRole(MemberRole.ADMIN.name())
                        .requestMatchers("/security-login/info").hasAnyRole(MemberRole.ADMIN.name(), MemberRole.USER.name())
                        .anyRequest().authenticated()
                );


        // 프레임 옵션 비활성화(H2 콘솔 접근을 위해)
        http
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.disable())
                );

        // 로그인 설정
        http
                .formLogin(auth -> auth
                        .loginPage("/security-login/login")
                        .loginProcessingUrl("/security-login/loginProc")
                        .failureUrl("/security-login/login")
                        .defaultSuccessUrl("/security-login")
                        .usernameParameter("loginId")
                        .passwordParameter("password")
                        .permitAll()
                );

        // 로그아웃 URL 설정
        http
                .logout(auth -> auth
                        .logoutUrl("/security-login/logout")
                );

        // csrf: 사이트 위변조 방지 설정(스프링 시큐리티에는 자동으로 설정되어 있음)
        // csrf 기능이 켜져있으면 post 요청을 보낼 때 csrf 토큰도 보내줘야 로그인 진행됨
        // 개발단계에서만 csrf 잠시 꺼두기
        http
                .csrf(auth -> auth.disable());

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
