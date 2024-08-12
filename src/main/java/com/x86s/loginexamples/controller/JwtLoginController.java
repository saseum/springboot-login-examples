package com.x86s.loginexamples.controller;

import com.x86s.loginexamples.domain.member.Member;
import com.x86s.loginexamples.domain.member.dto.JoinRequest;
import com.x86s.loginexamples.domain.member.dto.LoginRequest;
import com.x86s.loginexamples.jwt.JwtUtil;
import com.x86s.loginexamples.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
@RequestMapping("/jwt-login")
@RestController
public class JwtLoginController {

    private final MemberService memberService;
    private final JwtUtil jwtUtil;

    @GetMapping(value = {"", "/"})
    public String home(Model model) {
        setLoginType(model);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String loginId = authentication.getName();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> it = authorities.iterator();
        GrantedAuthority auth = it.next();
        String role = auth.getAuthority();

        Member loginMember = memberService.getLoginMemberByLoginId(loginId);

        if (loginMember != null) {
            model.addAttribute("name", loginMember.getName());
        }
        return "home";
    }

    @GetMapping("/join")
    public String joinPage(Model model) {
        setLoginType(model);

        // 회원가입을 위해 model 통해서 joinRequest 전달
        model.addAttribute("joinRequest", new JoinRequest());
        return "join";
    }

    @PostMapping("/join")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest, BindingResult bindingResult, Model model) {
        setLoginType(model);

        // ID 중복여부 확인
        if (memberService.checkLoginIdDuplicate(joinRequest.getLoginId())) {
            return "ID가 존재합니다.";
        }

        // 비밀번호, 비밀번호확인 값 동일여부 확인
        if (!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())) {
            return "비밀번호가 일치하지 않습니다.";
        }

        // 에러가 존재하지 않을 시 joinRequest 통해서 회원가입 완료
        memberService.securityJoin(joinRequest);

        return "redirect:/jwt-login";
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest loginRequest) {
        Member member = memberService.login(loginRequest);

        if (member == null) {
            return "ID 또는 비밀번호가 일치하지 않습니다.";
        }

        String token = jwtUtil.createJwt(member.getLoginId(), member.getRole().name(), 60 * 60 * 1000L);
        return token;
    }

    @GetMapping("/info")
    public String memberInfo(Authentication auth, Model model) {
        Member loginMember = memberService.getLoginMemberByLoginId(auth.getName());
        return String.format("ID: %s\n이름: %s\nRole: %s", loginMember.getLoginId(), loginMember.getName(), loginMember.getRole());
    }

    @GetMapping("/admin")
    public String adminPage(Model model) {
        return "Authorization success!";
    }

    private static void setLoginType(Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "스프링 시큐리티 JWT 로그인");
    }
}
