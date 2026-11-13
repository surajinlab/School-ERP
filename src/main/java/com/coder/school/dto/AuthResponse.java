package com.coder.school.dto;

public record AuthResponse(
        String message,
        String username,
        String role,
        String accessToken,
        String tokenType
) {
}