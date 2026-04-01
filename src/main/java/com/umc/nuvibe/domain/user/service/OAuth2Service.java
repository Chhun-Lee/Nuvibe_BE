package com.umc.nuvibe.domain.user.service;

import com.umc.nuvibe.domain.user.dto.request.OAuth2SignupReq;
import com.umc.nuvibe.domain.user.dto.response.OAuth2LoginRes;
import com.umc.nuvibe.global.security.oauth2.OAuth2UserInfo;
import com.umc.nuvibe.global.security.oauth2.OAuth2UserInfoFactory;
import com.umc.nuvibe.domain.user.vo.AuthProvider;
import com.umc.nuvibe.global.apiPayLoad.error.AuthErrorCode;
import com.umc.nuvibe.global.apiPayLoad.exception.BusinessException;
import com.umc.nuvibe.global.config.OAuth2Properties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final OAuth2UserService oAuth2UserService;
    private final OAuth2Properties oAuth2Properties;
    private final WebClient webClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(
                    HttpClient.create().responseTimeout(Duration.ofSeconds(10))
            ))
            .build();

    private final Map<String, String> redirectUriStore = new ConcurrentHashMap<>();
    private final Map<String, Long> stateStore = new ConcurrentHashMap<>();
    private static final long STATE_EXPIRY_MS = 5 * 60 * 1000;

    private static final List<String> ALLOWED_REDIRECT_URIS = List.of(
            "http://localhost:5173",
            "http://localhost:3000",
            "https://nuvibe.vercel.app"
    );


    public String getOAuthAuthorizationUrl(AuthProvider provider, String state) {
        stateStore.put(state, System.currentTimeMillis());

        return switch (provider) {
            case GOOGLE -> buildGoogleAuthUrl(state);
            case NAVER -> buildNaverAuthUrl(state);
            case KAKAO -> buildKakaoAuthUrl(state);
            default -> throw new BusinessException(AuthErrorCode.UNSUPPORTED_OAUTH_PROVIDER);
        };
    }

    public OAuth2LoginRes processOAuthCallback(AuthProvider provider, String code, String state) {
        // 트랜잭션 밖: state 검증 + 외부 API 호출
        validateState(state);
        String accessToken = getAccessToken(provider, code);
        Map<String, Object> attributes = fetchUserAttributes(provider, accessToken);
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(provider, attributes);

        // 트랜잭션 안: DB 작업 위임
        return oAuth2UserService.processOAuthUser(userInfo);
    }

    public void completeSignup(Long userId, OAuth2SignupReq request) {
        oAuth2UserService.completeSignup(userId, request);
    }

    public void saveRedirectUri(String state, String redirectUri) {
        if (redirectUri != null && isAllowedRedirectUri(redirectUri)) {
            redirectUriStore.put(state, redirectUri);
        }
    }

    public String getRedirectUri(String state, String defaultUrl) {
        String uri = redirectUriStore.remove(state);
        return uri != null ? uri : defaultUrl;
    }

    @Scheduled(fixedRate = 60000)
    public void cleanupExpiredStates() {
        long now = System.currentTimeMillis();
        stateStore.entrySet().removeIf(entry ->
                now - entry.getValue() > STATE_EXPIRY_MS);
    }

    // ========== State 검증 ==========

    private void validateState(String state) {
        if (state == null || state.isBlank()) {
            throw new BusinessException(AuthErrorCode.INVALID_OAUTH_STATE);
        }

        Long createdTime = stateStore.remove(state);

        if (createdTime == null) {
            throw new BusinessException(AuthErrorCode.INVALID_OAUTH_STATE);
        }

        if (System.currentTimeMillis() - createdTime > STATE_EXPIRY_MS) {
            throw new BusinessException(AuthErrorCode.OAUTH_STATE_EXPIRED);
        }
    }

    // ========== 외부 API 통신 ==========

    private String getAccessToken(AuthProvider provider, String code) {
        String tokenUrl = getTokenUrl(provider);
        MultiValueMap<String, String> params = buildTokenRequestParams(provider, code);

        try {
            Map<String, Object> response = webClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(params))
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .block();

            if (response != null && response.containsKey("access_token")) {
                return (String) response.get("access_token");
            }
            throw new BusinessException(AuthErrorCode.OAUTH_COMMUNICATION_ERROR);
        } catch (WebClientResponseException e) {
            log.error("OAuth token fetch failed: status={}, provider={}", e.getStatusCode(), provider);
            throw new BusinessException(AuthErrorCode.OAUTH_COMMUNICATION_ERROR);
        }
    }

    private Map<String, Object> fetchUserAttributes(AuthProvider provider, String accessToken) {
        String userInfoUrl = getUserInfoUrl(provider);

        try {
            Map<String, Object> attributes = webClient.get()
                    .uri(userInfoUrl)
                    .header("Authorization", "Bearer " + accessToken)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .block();
            if (attributes == null) {
                throw new BusinessException(AuthErrorCode.OAUTH_USER_INFO_NOT_FOUND);
            }
            return attributes;
        } catch (WebClientResponseException e) {
            log.error("OAuth user info fetch failed: status={}, provider={}", e.getStatusCode(), provider);
            throw new BusinessException(AuthErrorCode.OAUTH_USER_INFO_NOT_FOUND);
        } catch (Exception e) {
            log.error("OAuth communication error: provider={}", provider);
            throw new BusinessException(AuthErrorCode.OAUTH_COMMUNICATION_ERROR);
        }
    }

    // ========== URL Builders ==========

    private boolean isAllowedRedirectUri(String uri) {
        return ALLOWED_REDIRECT_URIS.stream().anyMatch(uri::startsWith);
    }

    private String getUserInfoUrl(AuthProvider provider) {
        return switch (provider) {
            case GOOGLE -> "https://www.googleapis.com/oauth2/v3/userinfo";
            case NAVER -> "https://openapi.naver.com/v1/nid/me";
            case KAKAO -> "https://kapi.kakao.com/v2/user/me";
            default -> throw new BusinessException(AuthErrorCode.UNSUPPORTED_OAUTH_PROVIDER);
        };
    }

    private String getTokenUrl(AuthProvider provider) {
        return switch (provider) {
            case GOOGLE -> "https://oauth2.googleapis.com/token";
            case NAVER -> "https://nid.naver.com/oauth2.0/token";
            case KAKAO -> "https://kauth.kakao.com/oauth/token";
            default -> throw new BusinessException(AuthErrorCode.UNSUPPORTED_OAUTH_PROVIDER);
        };
    }

    private MultiValueMap<String, String> buildTokenRequestParams(AuthProvider provider, String code) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);

        switch (provider) {
            case GOOGLE -> {
                params.add("client_id", oAuth2Properties.getGoogle().getClientId());
                params.add("client_secret", oAuth2Properties.getGoogle().getClientSecret());
                params.add("redirect_uri", oAuth2Properties.getGoogle().getRedirectUri());
            }
            case NAVER -> {
                params.add("client_id", oAuth2Properties.getNaver().getClientId());
                params.add("client_secret", oAuth2Properties.getNaver().getClientSecret());
                params.add("redirect_uri", oAuth2Properties.getNaver().getRedirectUri());
            }
            case KAKAO -> {
                params.add("client_id", oAuth2Properties.getKakao().getClientId());
                params.add("client_secret", oAuth2Properties.getKakao().getClientSecret());
                params.add("redirect_uri", oAuth2Properties.getKakao().getRedirectUri());
            }
            default -> throw new BusinessException(AuthErrorCode.UNSUPPORTED_OAUTH_PROVIDER);
        }

        return params;
    }

    private String buildGoogleAuthUrl(String state) {
        return UriComponentsBuilder.fromUriString("https://accounts.google.com/o/oauth2/v2/auth")
                .queryParam("client_id", oAuth2Properties.getGoogle().getClientId())
                .queryParam("redirect_uri", oAuth2Properties.getGoogle().getRedirectUri())
                .queryParam("response_type", "code")
                .queryParam("scope", "email profile")
                .queryParam("state", state)
                .build()
                .encode()
                .toUriString();
    }

    private String buildNaverAuthUrl(String state) {
        return UriComponentsBuilder.fromUriString("https://nid.naver.com/oauth2.0/authorize")
                .queryParam("client_id", oAuth2Properties.getNaver().getClientId())
                .queryParam("redirect_uri", oAuth2Properties.getNaver().getRedirectUri())
                .queryParam("response_type", "code")
                .queryParam("state", state)
                .build()
                .encode()
                .toUriString();
    }

    private String buildKakaoAuthUrl(String state) {
        return UriComponentsBuilder.fromUriString("https://kauth.kakao.com/oauth/authorize")
                .queryParam("client_id", oAuth2Properties.getKakao().getClientId())
                .queryParam("redirect_uri", oAuth2Properties.getKakao().getRedirectUri())
                .queryParam("response_type", "code")
                .queryParam("state", state)
                .build()
                .encode()
                .toUriString();
    }
}
