package com.shopeasy.api.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class DatabaseService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @PostConstruct
    public void initTables() {
        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """);

        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                price INT NOT NULL,
                image_url VARCHAR(500),
                category VARCHAR(100),
                stock INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """);

        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS cart_items (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NOT NULL,
                product_id BIGINT NOT NULL,
                quantity INT DEFAULT 1
            )
        """);

        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NOT NULL,
                total_amount INT NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """);

        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS order_items (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                order_id BIGINT NOT NULL,
                product_id BIGINT NOT NULL,
                product_name VARCHAR(255) NOT NULL,
                quantity INT NOT NULL,
                price INT NOT NULL
            )
        """);

        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS reviews (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                product_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                user_name VARCHAR(255) NOT NULL,
                rating INT NOT NULL,
                content TEXT,
                image_urls TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """);
    }

    // Generic query methods with snake_case -> camelCase conversion

    public List<Map<String, Object>> queryForList(String sql, Object... args) {
        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql, args);
        return results.stream()
                .map(this::toCamelCaseMap)
                .collect(Collectors.toList());
    }

    public Map<String, Object> queryForMap(String sql, Object... args) {
        Map<String, Object> result = jdbcTemplate.queryForMap(sql, args);
        return toCamelCaseMap(result);
    }

    public int update(String sql, Object... args) {
        return jdbcTemplate.update(sql, args);
    }

    public Long insertAndReturnId(String sql, Object... args) {
        jdbcTemplate.update(sql, args);
        return jdbcTemplate.queryForObject("SELECT LAST_INSERT_ID()", Long.class);
    }

    public <T> T queryForObject(String sql, Class<T> requiredType, Object... args) {
        return jdbcTemplate.queryForObject(sql, requiredType, args);
    }

    public JdbcTemplate getJdbcTemplate() {
        return jdbcTemplate;
    }

    private Map<String, Object> toCamelCaseMap(Map<String, Object> map) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String camelKey = toCamelCase(entry.getKey());
            result.put(camelKey, entry.getValue());
        }
        return result;
    }

    private String toCamelCase(String snakeCase) {
        if (snakeCase == null) return null;
        String lower = snakeCase.toLowerCase();
        StringBuilder result = new StringBuilder();
        boolean nextUpper = false;
        for (char c : lower.toCharArray()) {
            if (c == '_') {
                nextUpper = true;
            } else {
                if (nextUpper) {
                    result.append(Character.toUpperCase(c));
                    nextUpper = false;
                } else {
                    result.append(c);
                }
            }
        }
        return result.toString();
    }
}
