package com.x86s.loginexamples.controller;

import com.x86s.loginexamples.domain.member.Member;
import com.x86s.loginexamples.domain.member.MemberRole;
import com.x86s.loginexamples.domain.member.dto.JoinRequest;
import com.x86s.loginexamples.domain.member.dto.LoginRequest;
import com.x86s.loginexamples.service.MemberService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RequestMapping("/cookie-login")
@Controller
public class CookieLoginController {

    private final MemberService memberService;

    @GetMapping(value = {"", "/"})
    public String home(@CookieValue(name = "memberId", required = false) Long memberId, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        Member loginMember = memberService.getLoginMemberById(memberId);

        if (loginMember != null) {
            model.addAttribute("name", loginMember.getName());
        }

        return "home";
    }

    @GetMapping("/join")
    public String joinPage(Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        model.addAttribute("joinRequest", new JoinRequest());
        return "join";
    }

    @PostMapping("/join")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest, BindingResult bindingResult, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        // ID 중복여부 확인
        if (memberService.checkLoginIdDuplicate(joinRequest.getLoginId())) {
            bindingResult.addError(new FieldError(
                    "joinRequest",
                    "loginId",
                    "ID가 존재하지 않습니다."
            ));
        }

        // 비밀번호, 비밀번호체크값 일치여부 확인
        if (!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())) {
            bindingResult.addError(new FieldError(
                    "joinRequest",
                    "passwordCheck",
                    "비밀번호가 일치하지 않습니다."
            ));
        }

        // 에러가 존재할 시 다시 join.html로 전송
        if (bindingResult.hasErrors()) {
            return "join";
        }

        // 에러 미존재시 joinRequest 통해서 회원가입 완료
        memberService.join(joinRequest);

        return "redirect:/cookie-login";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        model.addAttribute("loginRequest", new LoginRequest());
        return "login";
    }

    @PostMapping("/login")
    public String login(@ModelAttribute LoginRequest loginRequest, BindingResult bindingResult, HttpServletResponse response, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        Member member = memberService.login(loginRequest);

        // ID나 비밀번호가 틀린 경우 global error 반환
        if (member == null) {
            bindingResult.reject("loginFail", "로그인 아이디 또는 비밀번호가 틀렸습니다.");
        }

        if (bindingResult.hasErrors()) {
            return "login";
        }

        // 로그인 성공 => 쿠키 생성
        Cookie cookie = new Cookie("memberId", String.valueOf(member.getId()));
        cookie.setMaxAge(60 * 60); // 쿠키 유효시간: 1시간
        response.addCookie(cookie);

        return "redirect:/cookie-login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        // 동일한 이름의 새 쿠키 생성 => 로그아웃
        Cookie cookie = new Cookie("memberId", null);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return "redirect:/cookie-login";
    }

    @GetMapping("/info")
    public String info(@CookieValue(name = "memberId", required = false) Long memberId, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        Member loginMember = memberService.getLoginMemberById(memberId);

        if (loginMember == null) {
            return "redirect:/cookie-login/login";
        }

        model.addAttribute("member", loginMember);
        return "info";
    }

    @GetMapping("/admin")
    public String adminPage(@CookieValue(name = "memberId", required = false) Long memberId, Model model) {
        model.addAttribute("loginType", "cookie-login");
        model.addAttribute("pageName", "쿠키 로그인");

        Member loginMember =memberService.getLoginMemberById(memberId);

        if (loginMember == null) {
            return "redirect:/cookie-login/login";
        }

        if (!loginMember.getRole().equals(MemberRole.ADMIN)) {
            return "redirect:/cookie-login";
        }

        return "admin";
    }

}
