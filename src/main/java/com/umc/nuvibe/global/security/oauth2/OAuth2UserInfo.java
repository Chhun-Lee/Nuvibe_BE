package com.umc.nuvibe.global.security.oauth2;

import com.umc.nuvibe.domain.user.vo.AuthProvider;

public interface OAuth2UserInfo {
    AuthProvider getProvider();
    String getProviderId();
    String getEmail();
}
