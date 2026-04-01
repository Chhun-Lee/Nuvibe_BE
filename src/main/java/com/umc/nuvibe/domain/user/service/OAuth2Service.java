package com.umc.nuvibe.domain.user.service;

import com.umc.nuvibe.domain.user.vo.AuthProvider;
import com.umc.nuvibe.global.apiPayLoad.error.AuthErrorCode;
import com.umc.nuvibe.global.apiPayLoad.exception.BusinessException;
import com.umc.nuvibe.global.security.oauth2.OAuth2ProviderClient;
import com.umc.nuvibe.domain.user.dto.response.OAuth2LoginRes;
import com.umc.nuvibe.domain.user.dto.request.OAuth2SignupReq;
import com.umc.nuvibe.global.security.oauth2.OAuth2UserInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Service
public class OAuth2Service {

    private final OAuth2UserService oAuth2UserService;
    private final Map<AuthProvider, OAuth2ProviderClient> providerClients;
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

    // Spring이 모든 OAuth2ProviderClient 구현체를 List로 주입 → Map으로 변환
    public OAuth2Service(OAuth2UserService oAuthUserService,
                        List<OAuth2ProviderClient> clients) {
        this.oAuth2UserService = oAuthUserService;
        this.providerClients = clients.stream()
                .collect(Collectors.toMap(
                        OAuth2ProviderClient::getProviderType,
                        Function.identity()
                ));
    }

    public String getOAuthAuthorizationUrl(AuthProvider provider, String state) {
        stateStore.put(state, System.currentTimeMillis());
        return getClient(provider).buildAuthorizationUrl(state);
    }

    public OAuth2LoginRes processOAuthCallback(AuthProvider provider, String code, String state) {
        validateState(state);
        OAuth2ProviderClient client = getClient(provider);

        String accessToken = getAccessToken(client, code);
        Map<String, Object> attributes = fetchUserAttributes(client, accessToken);
        OAuth2UserInfo userInfo = client.extractUserInfo(attributes);

        return oAuth2UserService.processOAuthUser(userInfo);
    }

    public void completeSignup(Long userId, OAuth2SignupReq request) {
        oAuth2UserService.completeSignup(userId, request);
    }



    private OAuth2ProviderClient getClient(AuthProvider provider) {
        OAuth2ProviderClient client = providerClients.get(provider);
        if (client == null) {
            throw new BusinessException(AuthErrorCode.UNSUPPORTED_OAUTH_PROVIDER);
        }
        return client;
    }



    private String getAccessToken(OAuth2ProviderClient client, String code) {
        MultiValueMap<String, String> params = client.buildTokenRequestParams(code);

        try {
            Map<String, Object> response = webClient.post()
                    .uri(client.getTokenUrl())
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
            log.error("OAuth token fetch failed: status={}, provider={}",
                    e.getStatusCode(), client.getProviderType());
            throw new BusinessException(AuthErrorCode.OAUTH_COMMUNICATION_ERROR);
        }
    }

    private Map<String, Object> fetchUserAttributes(OAuth2ProviderClient client, String accessToken) {
        try {
            Map<String, Object> attributes = webClient.get()
                    .uri(client.getUserInfoUrl())
                    .header("Authorization", "Bearer " + accessToken)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .block();
            if (attributes == null) {
                throw new BusinessException(AuthErrorCode.OAUTH_USER_INFO_NOT_FOUND);
            }
            return attributes;
        } catch (WebClientResponseException e) {
            log.error("OAuth user info fetch failed: status={}, provider={}",
                    e.getStatusCode(), client.getProviderType());
            throw new BusinessException(AuthErrorCode.OAUTH_USER_INFO_NOT_FOUND);
        } catch (Exception e) {
            log.error("OAuth communication error: provider={}", client.getProviderType());
            throw new BusinessException(AuthErrorCode.OAUTH_COMMUNICATION_ERROR);
        }
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

    private boolean isAllowedRedirectUri(String uri) {
        return ALLOWED_REDIRECT_URIS.stream().anyMatch(uri::startsWith);
    }
}
