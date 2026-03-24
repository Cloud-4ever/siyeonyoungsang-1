package com.shopeasy.api.controller;

import com.shopeasy.api.dto.request.ReviewRequest;
import com.shopeasy.api.security.CurrentUser;
import com.shopeasy.api.service.CacheService;
import com.shopeasy.api.service.ReviewStoreService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
public class ReviewController {

    @Autowired
    private ReviewStoreService reviewStoreService;

    @Autowired
    private CacheService cacheService;

    @SuppressWarnings("unchecked")
    @GetMapping("/api/products/{productId}/reviews")
    public ResponseEntity<?> getReviews(@PathVariable Long productId) {
        String cacheKey = "reviews:" + productId;

        Object cached = cacheService.get(cacheKey);
        if (cached != null) {
            return ResponseEntity.ok(Map.of("reviews", cached));
        }

        List<Map<String, Object>> reviews = reviewStoreService.getReviews(productId);

        cacheService.set(cacheKey, reviews, 60);

        return ResponseEntity.ok(Map.of("reviews", reviews));
    }

    @PostMapping("/api/products/{productId}/reviews")
    public ResponseEntity<?> createReview(
            @PathVariable Long productId,
            @RequestBody ReviewRequest request,
            HttpServletRequest httpRequest) {

        CurrentUser currentUser = (CurrentUser) httpRequest.getAttribute("currentUser");

        Map<String, Object> review = reviewStoreService.createReview(
                productId,
                currentUser.getId(),
                currentUser.getName(),
                request.getRating(),
                request.getContent(),
                request.getImageUrls()
        );

        // Invalidate cache
        cacheService.deleteByPattern("reviews:" + productId);

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("review", review));
    }
}
