package com.shopeasy.api.controller;

import com.shopeasy.api.dto.request.PresignedRequest;
import com.shopeasy.api.service.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/upload")
public class UploadController {

    @Autowired
    private StorageService storageService;

    private static final List<String> ALLOWED_TYPES = Arrays.asList(
            "image/jpeg", "image/png", "image/gif", "image/webp"
    );

    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

    @PostMapping
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "파일을 선택해주세요"));
        }

        if (file.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "파일 크기는 5MB 이하여야 합니다"));
        }

        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_TYPES.contains(contentType)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "이미지 파일만 업로드 가능합니다 (JPEG, PNG, GIF, WebP)"));
        }

        try {
            String fileUrl = storageService.uploadFile(file);
            return ResponseEntity.ok(Map.of("fileUrl", fileUrl));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "파일 업로드 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }

    @PostMapping("/presigned")
    public ResponseEntity<?> getPresignedUrl(@RequestBody PresignedRequest request) {
        try {
            Map<String, String> result = storageService.generatePresignedUrl(
                    request.getFileName(), request.getFileType()
            );
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Presigned URL 생성 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }
}
