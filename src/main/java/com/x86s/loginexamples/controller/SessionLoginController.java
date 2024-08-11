package com.x86s.loginexamples.controller;

import com.x86s.loginexamples.domain.member.Member;
import com.x86s.loginexamples.domain.member.MemberRole;
import com.x86s.loginexamples.domain.member.dto.JoinRequest;
import com.x86s.loginexamples.domain.member.dto.LoginRequest;
import com.x86s.loginexamples.service.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequiredArgsConstructor
@RequestMapping("/session-login")
@Controller
public class SessionLoginController {

    private final MemberService memberService;

    @GetMapping(value = {"", "/"})
    public String home(Model model, @SessionAttribute(name = "memberId", required = false) Long memberId) {
        setLoginType(model);

        Member loginMember = memberService.getLoginMemberById(memberId);

        // 로그인 되어있다면 model에 이름 속성 추가
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

        // ID 중복 여부 확인
        if (memberService.checkLoginIdDuplicate(joinRequest.getLoginId())) {
            bindingResult.addError(new FieldError("joinRequest", "loginId", "ID가 존재합니다."));
        }

        // 비밀번호, 비밀번호체크 동일여부 확인
        if (!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())) {
            bindingResult.addError(new FieldError("joinRequest", "passwordCheck", "비밀번호가 일치하지 않습니다."));
        }

        // 에러가 존재할 시 다시 join.html로 전송
        if (bindingResult.hasErrors()) {
            return "join";
        }

        // 에러가 존재하지 않을 시 joinRequest 통해서 회원가입 완료
        memberService.join(joinRequest);

        return "redirect:/session-login";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        setLoginType(model);

        model.addAttribute("loginRequest", new LoginRequest());
        return "login";
    }

    @PostMapping("/login")
    public String login(@ModelAttribute LoginRequest loginRequest, BindingResult bindingResult, HttpServletRequest request, Model model) {
        setLoginType(model);

        Member member = memberService.login(loginRequest);

        // ID나 비밀번호가 틀린 경우 Global Error 반환
        if (member == null) {
            bindingResult.reject("loginFail", "로그인 아이디 또는 비밀번호가 틀렸습니다.");
        }

        if (bindingResult.hasErrors()) {
            return "login";
        }

        // === 로그인 성공 => 세션 생성 및 속성 설정 ===

        // 기존 세션 무효화
        request.getSession().invalidate();

        // 세션 생성 => request에 연관된 세션이 없을 시 새로운 세션 생성 후 반환
        HttpSession session = request.getSession(true);

        // 세션에 {"memberId", memberId} 속성 추가
        session.setAttribute("memberId", member.getId());

        // 세션의 유효기간을 1시간으로 설정
        session.setMaxInactiveInterval(60 * 60);

        // =======

        return "redirect:/session-login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, Model model) {
        setLoginType(model);

        // request와 연관된 세션 불러옴(없으면 null 반환)
        HttpSession session = request.getSession(false);

        // 세션이 존재(== 로그인 되어있다)
        if (session != null) {
            // 로그인된 세션 무효화
            session.invalidate();
        }
        return "redirect:/session-login";
    }

    @GetMapping("/info")
    public String memberInfo(@SessionAttribute(name = "memberId", required = false) Long memberId, Model model) {
        setLoginType(model);

        Member loginMember = memberService.getLoginMemberById(memberId);

        if (loginMember == null) {
            return "redirect:/session-login/login";
        }

        model.addAttribute("member", loginMember);
        return "info";
    }

    @GetMapping("/admin")
    public String adminPage(@SessionAttribute(name = "memberId", required = false) Long memberId, Model model) {
        setLoginType(model);

        Member loginMember = memberService.getLoginMemberById(memberId);

        if (loginMember == null) {
            return "redirect:/session-login/login";
        }

        if (!loginMember.getRole().equals(MemberRole.ADMIN)) {
            return "redirect:/session-login";
        }
        return "admin";
    }

    private static void setLoginType(Model model) {
        model.addAttribute("loginType", "session-login");
        model.addAttribute("pageName", "세션 로그인");
    }
}
//D156CA87325AC89ABA494E2BE134C538//B79510F343A847AD5C04FACEAF728F0A
