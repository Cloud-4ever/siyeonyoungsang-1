package com.shopeasy.api.controller;

import com.shopeasy.api.security.CurrentUser;
import com.shopeasy.api.service.DatabaseService;
import com.shopeasy.api.service.QueueService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @Autowired
    private DatabaseService databaseService;

    @Autowired
    private QueueService queueService;

    @PostMapping
    public ResponseEntity<?> createOrder(HttpServletRequest request) {
        CurrentUser currentUser = (CurrentUser) request.getAttribute("currentUser");

        // Get cart items
        List<Map<String, Object>> cartItems = databaseService.queryForList(
                """
                SELECT ci.id, ci.product_id, ci.quantity,
                       p.name AS product_name, p.price AS product_price, p.stock
                FROM cart_items ci
                JOIN products p ON ci.product_id = p.id
                WHERE ci.user_id = ?
                """,
                currentUser.getId()
        );

        if (cartItems.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "장바구니가 비어있습니다"));
        }

        // Check stock for all items
        for (Map<String, Object> item : cartItems) {
            int stock = ((Number) item.get("stock")).intValue();
            int quantity = ((Number) item.get("quantity")).intValue();
            String productName = (String) item.get("productName");

            if (stock < quantity) {
                String error = String.format("'%s' 상품의 재고가 부족합니다 (재고: %d, 요청: %d)",
                        productName, stock, quantity);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", error));
            }
        }

        // Calculate total
        int totalAmount = 0;
        for (Map<String, Object> item : cartItems) {
            int price = ((Number) item.get("productPrice")).intValue();
            int quantity = ((Number) item.get("quantity")).intValue();
            totalAmount += price * quantity;
        }

        // Create order
        Long orderId = databaseService.insertAndReturnId(
                "INSERT INTO orders (user_id, total_amount, status) VALUES (?, ?, 'pending')",
                currentUser.getId(), totalAmount
        );

        // Create order items and update stock
        List<Map<String, Object>> orderItems = new ArrayList<>();
        for (Map<String, Object> item : cartItems) {
            Long productId = ((Number) item.get("productId")).longValue();
            String productName = (String) item.get("productName");
            int quantity = ((Number) item.get("quantity")).intValue();
            int price = ((Number) item.get("productPrice")).intValue();

            databaseService.update(
                    "INSERT INTO order_items (order_id, product_id, product_name, quantity, price) VALUES (?, ?, ?, ?, ?)",
                    orderId, productId, productName, quantity, price
            );

            // Update stock
            databaseService.update(
                    "UPDATE products SET stock = stock - ? WHERE id = ?",
                    quantity, productId
            );

            Map<String, Object> orderItem = new LinkedHashMap<>();
            orderItem.put("productId", productId);
            orderItem.put("productName", productName);
            orderItem.put("quantity", quantity);
            orderItem.put("price", price);
            orderItems.add(orderItem);
        }

        // Clear cart
        databaseService.update("DELETE FROM cart_items WHERE user_id = ?", currentUser.getId());

        // Get the created order
        Map<String, Object> order = databaseService.queryForMap(
                "SELECT * FROM orders WHERE id = ?", orderId
        );
        order.put("items", orderItems);

        // Send queue message
        queueService.sendOrderMessage(order);

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("order", order));
    }

    @GetMapping
    public ResponseEntity<?> getOrders(HttpServletRequest request) {
        CurrentUser currentUser = (CurrentUser) request.getAttribute("currentUser");

        List<Map<String, Object>> orders = databaseService.queryForList(
                "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
                currentUser.getId()
        );

        // Get order items for each order
        for (Map<String, Object> order : orders) {
            Long orderId = ((Number) order.get("id")).longValue();
            List<Map<String, Object>> items = databaseService.queryForList(
                    "SELECT product_id, product_name, quantity, price FROM order_items WHERE order_id = ?",
                    orderId
            );
            order.put("items", items);
        }

        return ResponseEntity.ok(Map.of("orders", orders));
    }
}
