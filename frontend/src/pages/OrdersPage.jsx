import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ordersAPI } from '../api';

function OrdersPage() {
  const { user, loading: authLoading } = useAuth();
  const navigate = useNavigate();
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!authLoading && !user) {
      navigate('/login');
      return;
    }

    if (user) {
      fetchOrders();
    }
  }, [user, authLoading, navigate]);

  const fetchOrders = async () => {
    setLoading(true);
    try {
      const res = await ordersAPI.getAll();
      setOrders(res.data.orders || []);
    } catch (err) {
      console.error('주문 내역 조회 실패:', err);
    } finally {
      setLoading(false);
    }
  };

  const formatPrice = (price) => {
    return price.toLocaleString('ko-KR') + '원';
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getStatusClass = (status) => {
    switch (status) {
      case 'completed':
        return 'order-status-completed';
      case 'cancelled':
        return 'order-status-cancelled';
      default:
        return 'order-status-pending';
    }
  };

  const getStatusLabel = (status) => {
    switch (status) {
      case 'completed':
        return '완료';
      case 'cancelled':
        return '취소됨';
      case 'pending':
        return '처리중';
      default:
        return status;
    }
  };

  if (authLoading || loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
      </div>
    );
  }

  return (
    <div className="orders-page">
      <h1 className="orders-page-title">주문 내역</h1>

      {orders.length === 0 ? (
        <div className="orders-empty">
          <p>주문 내역이 없습니다</p>
          <Link to="/" className="btn btn-primary" style={{ marginTop: '20px', display: 'inline-flex' }}>
            쇼핑하러 가기
          </Link>
        </div>
      ) : (
        <div className="order-list">
          {orders.map((order) => (
            <div key={order.id} className="order-card">
              <div className="order-card-header">
                <div>
                  <span className="order-card-id">주문번호: {order.id}</span>
                  <div className="order-card-date">{formatDate(order.createdAt)}</div>
                </div>
                <span className={`order-card-status ${getStatusClass(order.status)}`}>
                  {getStatusLabel(order.status)}
                </span>
              </div>

              <div className="order-card-items">
                {order.items &&
                  order.items.map((item, index) => (
                    <div key={index} className="order-card-item">
                      <span className="order-card-item-name">
                        {item.productName || `상품 #${item.productId}`}
                      </span>
                      <span className="order-card-item-qty">
                        {item.quantity}개
                      </span>
                      <span className="order-card-item-price">
                        {formatPrice(item.price * item.quantity)}
                      </span>
                    </div>
                  ))}
              </div>

              <div className="order-card-footer">
                <span className="order-card-total">
                  총 {formatPrice(order.totalAmount)}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default OrdersPage;
