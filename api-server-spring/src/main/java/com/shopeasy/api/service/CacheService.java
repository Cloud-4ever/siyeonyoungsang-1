package com.shopeasy.api.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
public class CacheService {

    private final ConcurrentHashMap<String, CacheEntry> memoryCache = new ConcurrentHashMap<>();

    @Value("${app.cache.type}")
    private String cacheType;

    public String getCacheType() {
        return cacheType;
    }

    public Object get(String key) {
        if ("redis".equals(cacheType)) {
            return null;
        }

        CacheEntry entry = memoryCache.get(key);
        if (entry != null && !entry.isExpired()) {
            return entry.getValue();
        }
        if (entry != null && entry.isExpired()) {
            memoryCache.remove(key);
        }
        return null;
    }

    public void set(String key, Object value, int ttlSeconds) {
        if ("redis".equals(cacheType)) {
            return;
        }

        memoryCache.put(key, new CacheEntry(value, ttlSeconds));
    }

    public void delete(String key) {
        if ("redis".equals(cacheType)) {
            return;
        }

        memoryCache.remove(key);
    }

    public void deleteByPattern(String pattern) {
        if ("redis".equals(cacheType)) {
            return;
        }

        String prefix = pattern.replace("*", "");
        memoryCache.keySet().removeIf(k -> k.startsWith(prefix));
    }

    private static class CacheEntry {
        private final Object value;
        private final long expiresAt;

        public CacheEntry(Object value, int ttlSeconds) {
            this.value = value;
            this.expiresAt = System.currentTimeMillis() + (ttlSeconds * 1000L);
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }

        public Object getValue() {
            return value;
        }
    }
}
