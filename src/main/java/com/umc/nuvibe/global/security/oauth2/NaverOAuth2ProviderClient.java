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
public class NaverOAuth2ProviderClient implements OAuth2ProviderClient {

    private final OAuth2Properties oAuth2Properties;

    @Override
    public AuthProvider getProviderType() {
        return AuthProvider.NAVER;
    }

    @Override
    public String buildAuthorizationUrl(String state) {
        return UriComponentsBuilder.fromUriString("https://nid.naver.com/oauth2.0/authorize")
                .queryParam("client_id", oAuth2Properties.getNaver().getClientId())
                .queryParam("redirect_uri", oAuth2Properties.getNaver().getRedirectUri())
                .queryParam("response_type", "code")
                .queryParam("state", state)
                .build().encode().toUriString();
    }

    @Override
    public String getTokenUrl() {
        return "https://nid.naver.com/oauth2.0/token";
    }

    @Override
    public String getUserInfoUrl() {
        return "https://openapi.naver.com/v1/nid/me";
    }

    @Override
    public MultiValueMap<String, String> buildTokenRequestParams(String code) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("client_id", oAuth2Properties.getNaver().getClientId());
        params.add("client_secret", oAuth2Properties.getNaver().getClientSecret());
        params.add("redirect_uri", oAuth2Properties.getNaver().getRedirectUri());
        return params;
    }

    @Override
    public OAuth2UserInfo extractUserInfo(Map<String, Object> attributes) {
        return new NaverOAuth2UserInfo(attributes);
    }
}
