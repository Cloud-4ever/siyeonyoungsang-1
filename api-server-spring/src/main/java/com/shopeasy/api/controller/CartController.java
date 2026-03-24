package com.shopeasy.api.controller;

import com.shopeasy.api.dto.request.CartRequest;
import com.shopeasy.api.security.CurrentUser;
import com.shopeasy.api.service.DatabaseService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/cart")
public class CartController {

    @Autowired
    private DatabaseService databaseService;

    @GetMapping
    public ResponseEntity<?> getCart(HttpServletRequest request) {
        CurrentUser currentUser = (CurrentUser) request.getAttribute("currentUser");

        List<Map<String, Object>> items = databaseService.queryForList(
                """
                SELECT ci.id, ci.product_id, ci.quantity,
                       p.name AS product_name, p.price AS product_price,
                       p.image_url AS product_image_url, p.stock
                FROM cart_items ci
                JOIN products p ON ci.product_id = p.id
                WHERE ci.user_id = ?
                """,
                currentUser.getId()
        );

        return ResponseEntity.ok(Map.of("items", items));
    }

    @PostMapping
    public ResponseEntity<?> addToCart(@RequestBody CartRequest cartRequest, HttpServletRequest request) {
        CurrentUser currentUser = (CurrentUser) request.getAttribute("currentUser");

        // Check if product exists
        try {
            databaseService.queryForMap("SELECT id FROM products WHERE id = ?", cartRequest.getProductId());
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "상품을 찾을 수 없습니다"));
        }

        // Check if already in cart
        List<Map<String, Object>> existing = databaseService.queryForList(
                "SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?",
                currentUser.getId(), cartRequest.getProductId()
        );

        Long itemId;
        if (!existing.isEmpty()) {
            // Update quantity
            itemId = ((Number) existing.get(0).get("id")).longValue();
            int newQuantity = ((Number) existing.get(0).get("quantity")).intValue() + cartRequest.getQuantity();
            databaseService.update("UPDATE cart_items SET quantity = ? WHERE id = ?", newQuantity, itemId);
        } else {
            // Insert new
            itemId = databaseService.insertAndReturnId(
                    "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
                    currentUser.getId(), cartRequest.getProductId(), cartRequest.getQuantity()
            );
        }

        Map<String, Object> item = databaseService.queryForMap(
                """
                SELECT ci.id, ci.product_id, ci.quantity,
                       p.name AS product_name, p.price AS product_price,
                       p.image_url AS product_image_url, p.stock
                FROM cart_items ci
                JOIN products p ON ci.product_id = p.id
                WHERE ci.id = ?
                """,
                itemId
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("item", item));
    }

    @PutMapping("/{itemId}")
    public ResponseEntity<?> updateCartItem(
            @PathVariable Long itemId,
            @RequestBody CartRequest cartRequest,
            HttpServletRequest request) {

        CurrentUser currentUser = (CurrentUser) request.getAttribute("currentUser");

        // Verify ownership
        List<Map<String, Object>> existing = databaseService.queryForList(
                "SELECT id FROM cart_items WHERE id = ? AND user_id = ?",
                itemId, currentUser.getId()
        );

        if (existing.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "장바구니 항목을 찾을 수 없습니다"));
        }

        if (cartRequest.getQuantity() <= 0) {
            databaseService.update("DELETE FROM cart_items WHERE id = ?", itemId);
            return ResponseEntity.ok(Map.of("success", true));
        }

        databaseService.update("UPDATE cart_items SET quantity = ? WHERE id = ?",
                cartRequest.getQuantity(), itemId);

        Map<String, Object> item = databaseService.queryForMap(
                """
                SELECT ci.id, ci.product_id, ci.quantity,
                       p.name AS product_name, p.price AS product_price,
                       p.image_url AS product_image_url, p.stock
                FROM cart_items ci
                JOIN products p ON ci.product_id = p.id
                WHERE ci.id = ?
                """,
                itemId
        );

        return ResponseEntity.ok(Map.of("item", item));
    }

    @DeleteMapping("/{itemId}")
    public ResponseEntity<?> deleteCartItem(@PathVariable Long itemId, HttpServletRequest request) {
        CurrentUser currentUser = (CurrentUser) request.getAttribute("currentUser");

        databaseService.update("DELETE FROM cart_items WHERE id = ? AND user_id = ?",
                itemId, currentUser.getId());

        return ResponseEntity.ok(Map.of("success", true));
    }

    @DeleteMapping
    public ResponseEntity<?> clearCart(HttpServletRequest request) {
        CurrentUser currentUser = (CurrentUser) request.getAttribute("currentUser");

        databaseService.update("DELETE FROM cart_items WHERE user_id = ?", currentUser.getId());

        return ResponseEntity.ok(Map.of("success", true));
    }
}
