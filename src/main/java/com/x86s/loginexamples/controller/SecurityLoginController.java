package com.x86s.loginexamples.controller;

import com.x86s.loginexamples.domain.member.Member;
import com.x86s.loginexamples.domain.member.dto.JoinRequest;
import com.x86s.loginexamples.domain.member.dto.LoginRequest;
import com.x86s.loginexamples.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
@RequestMapping("/security-login")
@Controller
public class SecurityLoginController {

    private final MemberService memberService;

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

        // 회원가입을 위해서 model을 통해서 joinRequest 전달
        model.addAttribute("joinRequest", new JoinRequest());
        return "join";
    }

    @PostMapping("/join")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest, BindingResult bindingResult, Model model) {
        setLoginType(model);

        // 비밀번호 암호화 추가한 회원가입 로직으로 회원가입
        memberService.securityJoin(joinRequest);

        return "redirect:/security-login";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        setLoginType(model);

        model.addAttribute("loginRequest", new LoginRequest());
        return "login";
    }

    @GetMapping("/info")
    public String memberInfo(Authentication auth, Model model) {
        setLoginType(model);

        Member loginMember = memberService.getLoginMemberByLoginId(auth.getName());

        model.addAttribute("member", loginMember);
        return "info";
    }

    @GetMapping("/admin")
    public String adminPage(Model model) {
        setLoginType(model);
        return "admin";
    }



    private static void setLoginType(Model model) {
        model.addAttribute("loginType", "security-login");
        model.addAttribute("pageName", "스프링 시큐리티 로그인");
    }
}
