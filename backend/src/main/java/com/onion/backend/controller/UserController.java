package com.onion.backend.controller;

import com.onion.backend.dto.SignUpUser;
import com.onion.backend.entity.User;
import com.onion.backend.jwt.JwtUtil;
import com.onion.backend.service.CustomUserDetailsService;
import com.onion.backend.service.JwtBlacklistService;
import com.onion.backend.service.UserService;
import io.swagger.v3.oas.annotations.Parameter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final CustomUserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final JwtBlacklistService jwtBlacklistService;

    @Autowired
    public UserController(UserService userService, CustomUserDetailsService userDetailsService, AuthenticationManager authenticationManager, JwtUtil jwtUtil, JwtBlacklistService jwtBlacklistService) {
        this.userService = userService;
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.jwtBlacklistService = jwtBlacklistService;
    }

    @GetMapping("")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok(userService.getUsers());
    }

    @PostMapping("/signUp")
    public ResponseEntity<User> createUser(@RequestBody SignUpUser signUpUser) {
        User user = userService.createUser(signUpUser); // 유저 생성 메서드 호출
        return ResponseEntity.ok(user);
    }

    // 유저 삭제 API
    @DeleteMapping("/{userId}")
    public ResponseEntity<String> deleteUser(@Parameter(description = "ID of the user to be deleted", required = true) @PathVariable Long userId) {
        userService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password, HttpServletResponse response) throws AuthenticationException {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//        return jwtUtil.generateToken(userDetails.getUsername());

        // jwt 로그아웃 방법 1. 클라이언트 측에서 토큰 삭제
        // 클라이언트(웹 브라우저, 모바일 앱)에서 jwt를 저장하는 localStorage나 sessionStorage, cookie에서 삭제하는 방법
        String token = jwtUtil.generateToken(userDetails.getUsername());
        Cookie cookie = new Cookie("onion_token", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60);  // 이미 발급된 토큰은 만료되기 전까지 유효하므로, JwtUtil에서 설정한 expirationTime과 동일하게 준다

        response.addCookie(cookie);
        return token;
    }

//    jwt 로그아웃 방법 2. 서버에서 블랙리스트를 활용한 로그아웃 > 여러 개의 기기에서 로그인 되어 있을 때 한 번의 로그아웃 용도 등으로 사용됨
//    서버에서 로그아웃된 토큰을 저장하여 이후 요청을 차단하는 방식
//    로그아웃 시, 사용자의 토큰을 Reddis 같은 인메모리 데이터베이스에 key-value 형태로 저장
//    강의에서는 mySql에 key-value 형태로 저장함으로써 구현

    @PostMapping("/logout")
    public void logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("onion_token", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // 쿠키 삭제
        response.addCookie(cookie);
    }

    @PostMapping("/logout/all")
    public void logout(@RequestParam(required = false) String requestToken, @CookieValue(value = "onion_token", required = false) String cookieToken, HttpServletRequest request, HttpServletResponse response) {
        String token = null;
        String bearerToken = request.getHeader("Authorization");
        if (requestToken != null) {
            token = requestToken;
        } else if (cookieToken != null) {
            token = cookieToken;
        } else if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            token = bearerToken.substring(7);
        }
        Instant instant = new Date().toInstant();
        LocalDateTime expirationTime = instant.atZone(ZoneId.systemDefault()).toLocalDateTime();
        String username = jwtUtil.getUsernameFromToken(token);
        // 전체 로그아웃 요청 기록 저장
        jwtBlacklistService.blacklistToken(token, expirationTime, username);
        Cookie cookie = new Cookie("onion_token", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // 쿠키 삭제
        response.addCookie(cookie);
    }

    @PostMapping("/token/validation")
    @ResponseStatus(HttpStatus.OK)  // 기본 상태 : 200
    public void jwtValidate(@RequestParam String token) {
        if (!jwtUtil.validateToken(token)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Token is not validation");
        }
    }
}
