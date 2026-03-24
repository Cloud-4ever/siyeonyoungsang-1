package com.shopeasy.api.controller;

import com.shopeasy.api.dto.request.LoginRequest;
import com.shopeasy.api.dto.request.SignupRequest;
import com.shopeasy.api.dto.response.AuthResponse;
import com.shopeasy.api.security.CurrentUser;
import com.shopeasy.api.security.JwtUtil;
import com.shopeasy.api.service.DatabaseService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private DatabaseService databaseService;

    @Autowired
    private JwtUtil jwtUtil;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest request) {
        try {
            String hashedPassword = passwordEncoder.encode(request.getPassword());

            Long id = databaseService.insertAndReturnId(
                    "INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)",
                    request.getEmail(), hashedPassword, request.getName()
            );

            String token = jwtUtil.generateToken(id, request.getEmail(), request.getName());

            Map<String, Object> user = new LinkedHashMap<>();
            user.put("id", id);
            user.put("email", request.getEmail());
            user.put("name", request.getName());

            return ResponseEntity.status(HttpStatus.CREATED).body(new AuthResponse(token, user));
        } catch (DuplicateKeyException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", "이미 사용 중인 이메일입니다"));
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("Unique index")) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(Map.of("error", "이미 사용 중인 이메일입니다"));
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            Map<String, Object> user = databaseService.queryForMap(
                    "SELECT * FROM users WHERE email = ?", request.getEmail()
            );

            String storedHash = (String) user.get("passwordHash");
            if (!passwordEncoder.matches(request.getPassword(), storedHash)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "이메일 또는 비밀번호가 일치하지 않습니다"));
            }

            Long id = ((Number) user.get("id")).longValue();
            String email = (String) user.get("email");
            String name = (String) user.get("name");

            String token = jwtUtil.generateToken(id, email, name);

            Map<String, Object> userResponse = new LinkedHashMap<>();
            userResponse.put("id", id);
            userResponse.put("email", email);
            userResponse.put("name", name);

            return ResponseEntity.ok(new AuthResponse(token, userResponse));
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "이메일 또는 비밀번호가 일치하지 않습니다"));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(HttpServletRequest request) {
        CurrentUser currentUser = (CurrentUser) request.getAttribute("currentUser");

        try {
            Map<String, Object> user = databaseService.queryForMap(
                    "SELECT id, email, name, created_at FROM users WHERE id = ?",
                    currentUser.getId()
            );

            return ResponseEntity.ok(Map.of("user", user));
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "사용자를 찾을 수 없습니다"));
        }
    }
}
