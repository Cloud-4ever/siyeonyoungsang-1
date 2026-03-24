package com.shopeasy.api.controller;

import com.shopeasy.api.service.CacheService;
import com.shopeasy.api.service.QueueService;
import com.shopeasy.api.service.ReviewStoreService;
import com.shopeasy.api.service.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class HealthController {

    @Value("${app.db.type}")
    private String dbType;

    @Autowired
    private CacheService cacheService;

    @Autowired
    private StorageService storageService;

    @Autowired
    private ReviewStoreService reviewStoreService;

    @Autowired
    private QueueService queueService;

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("dbType", dbType);
        config.put("storageType", storageService.getStorageType());
        config.put("reviewStore", reviewStoreService.getReviewStore());
        config.put("cacheType", cacheService.getCacheType());
        config.put("queueType", queueService.getQueueType());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "ok");
        response.put("timestamp", Instant.now().toString());
        response.put("config", config);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> config() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("storageType", storageService.getStorageType());
        response.put("reviewStore", reviewStoreService.getReviewStore());
        response.put("dbType", dbType);

        return ResponseEntity.ok(response);
    }
}
