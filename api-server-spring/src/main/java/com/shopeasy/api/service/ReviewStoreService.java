package com.shopeasy.api.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ReviewStoreService {

    @Value("${app.review.store}")
    private String reviewStore;

    @Value("${app.review.dynamodb.table:Reviews}")
    private String dynamoDbTable;

    @Autowired
    private DatabaseService databaseService;

    @Autowired
    @Lazy
    private DynamoDbClient dynamoDbClient;

    public String getReviewStore() {
        return reviewStore;
    }

    public List<Map<String, Object>> getReviews(Long productId) {
        if ("dynamodb".equals(reviewStore)) {
            return getReviewsFromDynamoDB(productId);
        }
        return databaseService.queryForList(
                "SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC",
                productId
        ).stream().map(review -> {
            Object imageUrlsObj = review.get("imageUrls");
            if (imageUrlsObj instanceof String str && !str.isEmpty()) {
                try {
                    String cleaned = str.replace("[", "").replace("]", "").replace("\"", "");
                    if (!cleaned.isEmpty()) {
                        review.put("imageUrls", Arrays.asList(cleaned.split(",")));
                    } else {
                        review.put("imageUrls", new ArrayList<>());
                    }
                } catch (Exception e) {
                    review.put("imageUrls", new ArrayList<>());
                }
            } else {
                review.put("imageUrls", new ArrayList<>());
            }
            return review;
        }).collect(Collectors.toList());
    }

    public Map<String, Object> createReview(Long productId, Long userId, String userName, int rating, String content, List<String> imageUrls) {
        if ("dynamodb".equals(reviewStore)) {
            return createReviewInDynamoDB(productId, userId, userName, rating, content, imageUrls);
        }

        String imageUrlsJson = "[]";
        if (imageUrls != null && !imageUrls.isEmpty()) {
            imageUrlsJson = "[" + imageUrls.stream()
                    .map(url -> "\"" + url + "\"")
                    .collect(Collectors.joining(",")) + "]";
        }

        Long id = databaseService.insertAndReturnId(
                "INSERT INTO reviews (product_id, user_id, user_name, rating, content, image_urls) VALUES (?, ?, ?, ?, ?, ?)",
                productId, userId, userName, rating, content, imageUrlsJson
        );

        Map<String, Object> review = databaseService.queryForMap(
                "SELECT * FROM reviews WHERE id = ?", id
        );

        Object imageUrlsObj = review.get("imageUrls");
        if (imageUrlsObj instanceof String str && !str.isEmpty()) {
            try {
                String cleaned = str.replace("[", "").replace("]", "").replace("\"", "");
                if (!cleaned.isEmpty()) {
                    review.put("imageUrls", Arrays.asList(cleaned.split(",")));
                } else {
                    review.put("imageUrls", imageUrls != null ? imageUrls : new ArrayList<>());
                }
            } catch (Exception e) {
                review.put("imageUrls", imageUrls != null ? imageUrls : new ArrayList<>());
            }
        } else {
            review.put("imageUrls", imageUrls != null ? imageUrls : new ArrayList<>());
        }

        return review;
    }

    private List<Map<String, Object>> getReviewsFromDynamoDB(Long productId) {
        try {
            QueryRequest request = QueryRequest.builder()
                    .tableName(dynamoDbTable)
                    .keyConditionExpression("productId = :pid")
                    .expressionAttributeValues(Map.of(
                            ":pid", AttributeValue.builder().n(productId.toString()).build()
                    ))
                    .scanIndexForward(false)
                    .build();

            QueryResponse response = dynamoDbClient.query(request);

            return response.items().stream()
                    .map(this::dynamoItemToMap)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            System.err.println("DynamoDB query error: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    private Map<String, Object> createReviewInDynamoDB(Long productId, Long userId, String userName, int rating, String content, List<String> imageUrls) {
        String id = UUID.randomUUID().toString();
        String createdAt = Instant.now().toString();

        Map<String, AttributeValue> item = new HashMap<>();
        item.put("id", AttributeValue.builder().s(id).build());
        item.put("productId", AttributeValue.builder().n(productId.toString()).build());
        item.put("userId", AttributeValue.builder().n(userId.toString()).build());
        item.put("userName", AttributeValue.builder().s(userName).build());
        item.put("rating", AttributeValue.builder().n(String.valueOf(rating)).build());
        item.put("content", AttributeValue.builder().s(content != null ? content : "").build());
        item.put("createdAt", AttributeValue.builder().s(createdAt).build());

        if (imageUrls != null && !imageUrls.isEmpty()) {
            item.put("imageUrls", AttributeValue.builder().l(
                    imageUrls.stream()
                            .map(url -> AttributeValue.builder().s(url).build())
                            .collect(Collectors.toList())
            ).build());
        } else {
            item.put("imageUrls", AttributeValue.builder().l(Collections.emptyList()).build());
        }

        PutItemRequest putRequest = PutItemRequest.builder()
                .tableName(dynamoDbTable)
                .item(item)
                .build();

        dynamoDbClient.putItem(putRequest);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", id);
        result.put("productId", productId);
        result.put("userId", userId);
        result.put("userName", userName);
        result.put("rating", rating);
        result.put("content", content);
        result.put("imageUrls", imageUrls != null ? imageUrls : new ArrayList<>());
        result.put("createdAt", createdAt);

        return result;
    }

    private Map<String, Object> dynamoItemToMap(Map<String, AttributeValue> item) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", item.containsKey("id") ? item.get("id").s() : null);
        map.put("productId", item.containsKey("productId") ? Long.parseLong(item.get("productId").n()) : null);
        map.put("userId", item.containsKey("userId") ? Long.parseLong(item.get("userId").n()) : null);
        map.put("userName", item.containsKey("userName") ? item.get("userName").s() : null);
        map.put("rating", item.containsKey("rating") ? Integer.parseInt(item.get("rating").n()) : null);
        map.put("content", item.containsKey("content") ? item.get("content").s() : null);
        map.put("createdAt", item.containsKey("createdAt") ? item.get("createdAt").s() : null);

        if (item.containsKey("imageUrls") && item.get("imageUrls").l() != null) {
            map.put("imageUrls", item.get("imageUrls").l().stream()
                    .map(AttributeValue::s)
                    .collect(Collectors.toList()));
        } else {
            map.put("imageUrls", new ArrayList<>());
        }

        return map;
    }
}
