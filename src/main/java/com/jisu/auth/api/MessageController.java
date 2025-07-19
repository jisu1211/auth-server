package com.jisu.auth.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class MessageController {
    /**
     * 이 엔드포인트는 "message.read" 스코프 권한이 있는
     * 유효한 Access Token을 제시해야만 접근할 수 있습니다.
     */
    @GetMapping("/api/messages")
    @PreAuthorize("hasAuthority('SCOPE_message.read')")
    public Map<String, String> getMessages() {
        return Map.of("message", "This is a protected resource!");
    }
}
