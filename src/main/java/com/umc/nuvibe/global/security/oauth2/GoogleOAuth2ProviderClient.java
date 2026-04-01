package com.umc.nuvibe.global.security.oauth2;

import com.umc.nuvibe.domain.user.vo.AuthProvider;
import com.umc.nuvibe.global.config.OAuth2Properties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class GoogleOAuth2ProviderClient implements OAuth2ProviderClient {

    private final OAuth2Properties oAuth2Properties;

    @Override
    public AuthProvider getProviderType() {
        return AuthProvider.GOOGLE;
    }

    @Override
    public String buildAuthorizationUrl(String state) {
        return UriComponentsBuilder.fromUriString("https://accounts.google.com/o/oauth2/v2/auth")
                .queryParam("client_id", oAuth2Properties.getGoogle().getClientId())
                .queryParam("redirect_uri", oAuth2Properties.getGoogle().getRedirectUri())
                .queryParam("response_type", "code")
                .queryParam("scope", "email profile")
                .queryParam("state", state)
                .build().encode().toUriString();
    }

    @Override
    public String getTokenUrl() {
        return "https://oauth2.googleapis.com/token";
    }

    @Override
    public String getUserInfoUrl() {
        return "https://www.googleapis.com/oauth2/v3/userinfo";
    }

    @Override
    public MultiValueMap<String, String> buildTokenRequestParams(String code) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("client_id", oAuth2Properties.getGoogle().getClientId());
        params.add("client_secret", oAuth2Properties.getGoogle().getClientSecret());
        params.add("redirect_uri", oAuth2Properties.getGoogle().getRedirectUri());
        return params;
    }

    @Override
    public OAuth2UserInfo extractUserInfo(Map<String, Object> attributes) {
        return new GoogleOAuth2UserInfo(attributes);
    }
}
