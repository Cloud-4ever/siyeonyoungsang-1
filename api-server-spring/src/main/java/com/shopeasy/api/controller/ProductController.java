package com.shopeasy.api.controller;

import com.shopeasy.api.service.CacheService;
import com.shopeasy.api.service.DatabaseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    @Autowired
    private DatabaseService databaseService;

    @Autowired
    private CacheService cacheService;

    @SuppressWarnings("unchecked")
    @GetMapping
    public ResponseEntity<?> getProducts(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String search) {

        String cacheKey = "products:" + (category != null ? category : "") + ":" + (search != null ? search : "");

        Object cached = cacheService.get(cacheKey);
        if (cached != null) {
            return ResponseEntity.ok(Map.of("products", cached));
        }

        StringBuilder sql = new StringBuilder("SELECT * FROM products WHERE 1=1");
        java.util.ArrayList<Object> params = new java.util.ArrayList<>();

        if (category != null && !category.isEmpty()) {
            sql.append(" AND category = ?");
            params.add(category);
        }

        if (search != null && !search.isEmpty()) {
            sql.append(" AND (name LIKE ? OR description LIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
        }

        sql.append(" ORDER BY created_at DESC");

        List<Map<String, Object>> products = databaseService.queryForList(
                sql.toString(), params.toArray()
        );

        cacheService.set(cacheKey, products, 60);

        return ResponseEntity.ok(Map.of("products", products));
    }

    @SuppressWarnings("unchecked")
    @GetMapping("/{id}")
    public ResponseEntity<?> getProduct(@PathVariable Long id) {
        String cacheKey = "product:" + id;

        Object cached = cacheService.get(cacheKey);
        if (cached != null) {
            return ResponseEntity.ok(Map.of("product", cached));
        }

        try {
            Map<String, Object> product = databaseService.queryForMap(
                    "SELECT * FROM products WHERE id = ?", id
            );

            cacheService.set(cacheKey, product, 120);

            return ResponseEntity.ok(Map.of("product", product));
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "상품을 찾을 수 없습니다"));
        }
    }
}
