package com.shopeasy.api.security;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.util.Map;

@Component
public class AuthInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtUtil jwtUtil;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Skip OPTIONS requests (CORS preflight)
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        // GET requests to /api/products/** are public (product list, detail, reviews)
        String method = request.getMethod();
        String path = request.getRequestURI();
        if ("GET".equalsIgnoreCase(method) && path.startsWith("/api/products")) {
            return true;
        }

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || authHeader.isEmpty()) {
            sendError(response, 401, "인증 토큰이 필요합니다");
            return false;
        }

        if (!authHeader.startsWith("Bearer ")) {
            sendError(response, 401, "올바른 토큰 형식이 아닙니다 (Bearer <token>)");
            return false;
        }

        String token = authHeader.substring(7);

        try {
            CurrentUser user = jwtUtil.extractUser(token);
            request.setAttribute("currentUser", user);
            return true;
        } catch (ExpiredJwtException e) {
            sendError(response, 401, "토큰이 만료되었습니다");
            return false;
        } catch (Exception e) {
            sendError(response, 401, "유효하지 않은 토큰입니다");
            return false;
        }
    }

    private void sendError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(Map.of("error", message)));
    }
}
