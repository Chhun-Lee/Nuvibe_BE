package com.umc.nuvibe.domain.user.service;

import com.umc.nuvibe.domain.user.dto.request.OAuth2SignupReq;
import com.umc.nuvibe.domain.user.dto.response.OAuth2LoginRes;
import com.umc.nuvibe.domain.user.entity.User;
import com.umc.nuvibe.global.security.oauth2.OAuth2UserInfo;
import com.umc.nuvibe.domain.user.repository.UserRepository;
import com.umc.nuvibe.global.apiPayLoad.error.AuthErrorCode;
import com.umc.nuvibe.global.apiPayLoad.error.UserErrorCode;
import com.umc.nuvibe.global.apiPayLoad.exception.BusinessException;
import com.umc.nuvibe.global.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class OAuth2UserService {

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public OAuth2LoginRes processOAuthUser(OAuth2UserInfo userInfo) {
        String email = userInfo.getEmail();
        if (email == null || email.isBlank()) {
            throw new BusinessException(AuthErrorCode.OAUTH_EMAIL_NOT_PROVIDED);
        }

        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent() && existingUser.get().getProvider() != userInfo.getProvider()) {
            throw new BusinessException(AuthErrorCode.OAUTH_EMAIL_ALREADY_REGISTERED);
        }

        boolean isNewUser = existingUser.isEmpty();
        User user = existingUser.orElseGet(() -> createNewOAuthUser(userInfo));

        String accessToken = jwtTokenProvider.createAccessToken(user, userInfo.getProvider());
        String refreshToken = jwtTokenProvider.createRefreshToken(user, userInfo.getProvider());

        user.updateRefreshToken(refreshToken);

        return new OAuth2LoginRes(
                accessToken, refreshToken, isNewUser,
                user.getId(), user.getEmail(), user.getProvider()
        );
    }

    private User createNewOAuthUser(OAuth2UserInfo userInfo) {
        User newUser = User.createSocialUser(
                userInfo.getEmail(),
                userInfo.getProvider(),
                userInfo.getProviderId()
        );
        return userRepository.save(newUser);
    }

    @Transactional
    public void completeSignup(Long userId, OAuth2SignupReq request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(UserErrorCode.USER_NOT_FOUND));

        user.createName(request.name());
        user.updateNickname(request.nickname());
    }
}
