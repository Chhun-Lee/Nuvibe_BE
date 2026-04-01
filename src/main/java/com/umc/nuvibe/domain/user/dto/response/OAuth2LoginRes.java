package com.umc.nuvibe.domain.user.dto.response;

import com.umc.nuvibe.domain.user.vo.AuthProvider;

public record OAuth2LoginRes(
        String accessToken,
        String refreshToken,
        boolean isNewUser,
        Long userId,
        String email,
        AuthProvider provider
) { }
