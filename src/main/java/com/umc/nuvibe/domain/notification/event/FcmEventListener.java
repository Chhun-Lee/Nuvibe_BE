package com.umc.nuvibe.domain.notification.event;

import com.umc.nuvibe.domain.notification.service.FcmAsyncService;
import com.umc.nuvibe.domain.user.entity.User;
import com.umc.nuvibe.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class FcmEventListener {

    private final FcmAsyncService fcmAsyncService;
    private final UserRepository userRepository;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handle(NotificationEvent event) {

        if (event.targetUserId() != null) {
            // 단일 수신자
            User user = userRepository.findById(event.targetUserId()).orElse(null);
            if (user == null) return;
            fcmAsyncService.sendNotification(user, event.type(), event.tag(),
                    event.relatedId(), event.tribeId());

        } else if (event.targetUserIds() != null && !event.targetUserIds().isEmpty()) {
            // 다수 수신자
            List<User> users = userRepository.findAllById(event.targetUserIds());
            for (User user : users) {
                fcmAsyncService.sendNotification(user, event.type(), event.tag(),
                        event.relatedId(), event.tribeId());
            }
        }
    }
}
