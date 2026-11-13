package com.coder.school.service;

import com.coder.school.dto.AuthResponse;
import com.coder.school.dto.LoginRequest;
import com.coder.school.dto.SignupRequest;
import com.coder.school.entity.AppUser;
import com.coder.school.jwt.JwtService;
import com.coder.school.repository.AppUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {

    private final JwtService jwtService;
    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthService(
            JwtService jwtService,
            AppUserRepository repository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager) {

        this.jwtService = jwtService;
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;

    }

    // SIGNUP
    public AuthResponse signup(SignupRequest request) {

        if (repository.existsByUsername(request.username())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "Username already exists"
            );
        }

        AppUser user = new AppUser();

        user.setUsername(request.username());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setRole(request.role());

        repository.save(user);

        return new AuthResponse(
                "Signup successful",
                user.getUsername(),
                user.getRole(),
                "AcessToken",
                "TokenType"
        );
    }

    // LOGIN
    public AuthResponse login(LoginRequest request) {

        // 1. Authenticate user
        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.username(),
                                request.password()
                        )
                );

        // 2. Get authenticated user
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // 3. Generate JWT
        String token = jwtService.generateToken(userDetails);

        // 4. Get role
        String role = userDetails.getAuthorities()
                .stream()
                .findFirst()
                .map(authority -> authority.getAuthority()
                        .replace("ROLE_", ""))
                .orElse("");

        // 5. Return response
        return new AuthResponse(
                "Login successful",
                userDetails.getUsername(),
                role,
                token,
                "Bearer"
        );
    }

//    public AuthResponse login(
//            LoginRequest request,
//            HttpServletRequest httpRequest,
//            HttpServletResponse httpResponse) {
//
//        try {
//            Authentication authentication = authenticationManager.authenticate(
//                            new UsernamePasswordAuthenticationToken(
//                                    request.username(),
//                                    request.password()
//                            )
//                    );
//
//            SecurityContext context = SecurityContextHolder.createEmptyContext();
//
//            context.setAuthentication(authentication);
//
//            SecurityContextHolder.setContext(context);
//
//            securityContextRepository.saveContext(
//                    context,
//                    httpRequest,
//                    httpResponse
//            );
//
//            AppUser user = repository
//                    .findByUsername(request.username())
//                    .orElseThrow();
//
//            return new AuthResponse(
//                    "Login successful",
//                    user.getUsername(),
//                    user.getRole()
//            );
//
//        } catch (AuthenticationException exception) {
//
//            SecurityContextHolder.clearContext();
//
//            throw new ResponseStatusException(
//                    HttpStatus.UNAUTHORIZED,
//                    "Invalid username or password"
//            );
//        }
//    }

    // LOGOUT
    public String logout(HttpServletRequest request) {

        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }

        SecurityContextHolder.clearContext();

        return "Logout successful";
    }
}