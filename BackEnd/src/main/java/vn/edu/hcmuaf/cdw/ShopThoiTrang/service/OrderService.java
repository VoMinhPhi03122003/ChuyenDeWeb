package vn.edu.hcmuaf.cdw.ShopThoiTrang.service;

import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.entity.Order;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.model.dto.CreateOrderRequest;

public interface OrderService {

    Page<Order> getAllOrders(String filter, int page, int perPage, String sortBy, String order);

    Order getOrderById(Long id);

    ResponseEntity<?> createOrder(CreateOrderRequest order);

    ResponseEntity<?> updateOrderStatus(Long orderId, Long orderStatusId);

    ResponseEntity<?> exportOrder(Long orderId);
}
