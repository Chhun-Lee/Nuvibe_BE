package com.umc.nuvibe.global.security.oauth2;

import com.umc.nuvibe.domain.user.vo.AuthProvider;
import org.springframework.util.MultiValueMap;

import java.util.Map;

public interface OAuth2ProviderClient {
    AuthProvider getProviderType();
    String buildAuthorizationUrl(String state);
    String getTokenUrl();
    String getUserInfoUrl();
    MultiValueMap<String, String> buildTokenRequestParams(String code);
    OAuth2UserInfo extractUserInfo(Map<String, Object> attributes);
}
