package com.umc.nuvibe.domain.notification.event;

import com.umc.nuvibe.domain.notification.vo.NotificationType;

import java.util.List;

public record NotificationEvent(
        NotificationType type,
        String tag,
        Long relatedId, // id만 넘기기 준영속 문제 차단
        Long tribeId,
        Long targetUserId,         // 단일 수신자
        List<Long> targetUserIds   // 다수 수신자
) {

    // 단일 사용자 알림 (NOTI_03, 10, 11)
    public static NotificationEvent forUser(NotificationType type, Long userId,
                                            String tag, Long relatedId, Long tribeId) {
        return new NotificationEvent(type, tag, relatedId, tribeId, userId, null);
    }

    // 다수 사용자 알림 (NOTI_01, 02, 05)
    public static NotificationEvent forUsers(NotificationType type, List<Long> userIds,
                                             String tag, Long relatedId, Long tribeId) {
        return new NotificationEvent(type, tag, relatedId, tribeId, null, userIds);
    }
}