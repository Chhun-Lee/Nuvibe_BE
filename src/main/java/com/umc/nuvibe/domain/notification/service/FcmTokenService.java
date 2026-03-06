package com.umc.nuvibe.domain.notification.service;

import com.umc.nuvibe.domain.notification.entity.Fcm;
import com.umc.nuvibe.domain.notification.repository.FcmRepository;
import com.umc.nuvibe.domain.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.umc.nuvibe.domain.user.repository.UserRepository;
import com.umc.nuvibe.global.apiPayLoad.error.UserErrorCode;
import com.umc.nuvibe.global.apiPayLoad.exception.BusinessException;
import java.util.Optional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class FcmTokenService {

    private final FcmRepository fcmRepository;
    private final UserRepository userRepository;

    @Transactional
    public void registerToken(Long userId, String token) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(UserErrorCode.USER_NOT_FOUND));

        // 같은 토큰의 다른 유저 행 비활성화
        List<Fcm> otherUserTokens = fcmRepository.findByTokenAndIsActiveTrueAndUserNot(token, user);
        otherUserTokens.forEach(Fcm::deactivate);

        // 같은 유저 + 같은 토큰 행 조회
        Optional<Fcm> existing = fcmRepository.findByUserAndToken(user, token);
        if (existing.isPresent()) {
            existing.get().activate();
        } else {
            fcmRepository.save(Fcm.builder()
                    .user(user)
                    .token(token)
                    .build());
        }
    }

    @Transactional
    public void deactivateToken(String token) {
        List<Fcm> fcmList = fcmRepository.findByToken(token);
        fcmList.forEach(Fcm::deactivate);
    }

    @Transactional
    public void deactivateAllTokens(User user) {
        List<Fcm> tokens = fcmRepository.findByUserAndIsActiveTrue(user);
        tokens.forEach(Fcm::deactivate);
    }
}
