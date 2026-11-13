package com.coder.school.controller;

import com.coder.school.dto.AuthResponse;
import com.coder.school.dto.LoginRequest;
import com.coder.school.dto.SignupRequest;
import com.coder.school.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // SIGNUP
    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request) {

        return ResponseEntity.ok(authService.signup(request));
    }

    // LOGIN
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {

        return ResponseEntity.ok(authService.login(request));
    }

    // LOGOUT
    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {

        return ResponseEntity.ok(authService.logout(request));
    }
}