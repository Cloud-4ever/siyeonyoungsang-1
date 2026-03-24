import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useCart } from '../context/CartContext';
import { ordersAPI } from '../api';

const categoryColors = ['#3498db', '#9b59b6', '#27ae60', '#f39c12', '#e74c3c'];

function CartPage() {
  const { user } = useAuth();
  const { items, loading, updateQuantity, removeItem, getCartTotal, fetchCart } = useCart();
  const navigate = useNavigate();
  const [ordering, setOrdering] = useState(false);
  const [orderSuccess, setOrderSuccess] = useState(false);
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  };

  const formatPrice = (price) => {
    return price.toLocaleString('ko-KR') + '원';
  };

  const handleQuantityChange = async (itemId, newQuantity) => {
    if (newQuantity < 1) return;
    try {
      await updateQuantity(itemId, newQuantity);
    } catch (err) {
      showToast('수량 변경에 실패했습니다', 'error');
    }
  };

  const handleRemoveItem = async (itemId) => {
    try {
      await removeItem(itemId);
      showToast('상품이 삭제되었습니다');
    } catch (err) {
      showToast('삭제에 실패했습니다', 'error');
    }
  };

  const handleOrder = async () => {
    if (items.length === 0) return;
    setOrdering(true);
    try {
      await ordersAPI.create();
      setOrderSuccess(true);
      await fetchCart();
    } catch (err) {
      console.error('주문 실패:', err);
      showToast('주문에 실패했습니다', 'error');
    } finally {
      setOrdering(false);
    }
  };

  if (!user) {
    return (
      <div className="cart-page">
        <div className="cart-empty">
          <div className="cart-empty-icon">🛒</div>
          <p className="cart-empty-text">로그인이 필요합니다</p>
          <Link to="/login" className="btn btn-primary">
            로그인하기
          </Link>
        </div>
      </div>
    );
  }

  if (orderSuccess) {
    return (
      <div className="cart-page">
        <div className="success-message">
          <div className="success-icon">&#10003;</div>
          <h2 className="success-text">주문이 완료되었습니다!</h2>
          <p className="success-subtext">주문 내역에서 확인하실 수 있습니다</p>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
            <button
              className="btn btn-primary"
              onClick={() => navigate('/orders')}
            >
              주문 내역 보기
            </button>
            <button
              className="btn btn-outline"
              onClick={() => navigate('/')}
            >
              계속 쇼핑하기
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="cart-page">
        <h1 className="cart-page-title">장바구니</h1>
        <div className="cart-empty">
          <div className="cart-empty-icon">🛒</div>
          <p className="cart-empty-text">장바구니가 비어있습니다</p>
          <Link to="/" className="btn btn-primary">
            쇼핑하러 가기
          </Link>
        </div>
      </div>
    );
  }

  const total = getCartTotal();
  const totalItems = items.reduce((sum, item) => sum + item.quantity, 0);

  return (
    <>
      <div className="cart-page">
        <h1 className="cart-page-title">장바구니</h1>

        <div className="cart-layout">
          <div className="cart-items">
            {items.map((item, index) => (
              <div key={item.id} className="cart-item">
                <div className="cart-item-image">
                  {item.productImageUrl ? (
                    <img
                      src={item.productImageUrl}
                      alt={item.productName}
                      onError={(e) => {
                        e.target.style.display = 'none';
                        e.target.nextSibling.style.display = 'flex';
                      }}
                    />
                  ) : null}
                  <div
                    className="cart-item-placeholder"
                    style={{
                      backgroundColor: categoryColors[index % categoryColors.length],
                      display: item.productImageUrl ? 'none' : 'flex',
                    }}
                  >
                    {item.productName}
                  </div>
                </div>

                <div className="cart-item-info">
                  <p className="cart-item-name">{item.productName}</p>
                  <p className="cart-item-price">{formatPrice(item.productPrice)}</p>
                </div>

                <div className="cart-item-controls">
                  <div className="quantity-selector">
                    <button
                      onClick={() =>
                        handleQuantityChange(item.id, item.quantity - 1)
                      }
                      disabled={item.quantity <= 1}
                    >
                      -
                    </button>
                    <span>{item.quantity}</span>
                    <button
                      onClick={() =>
                        handleQuantityChange(item.id, item.quantity + 1)
                      }
                    >
                      +
                    </button>
                  </div>
                  <button
                    className="cart-item-remove"
                    onClick={() => handleRemoveItem(item.id)}
                  >
                    삭제
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div className="cart-summary">
            <h2 className="cart-summary-title">주문 요약</h2>
            <div className="cart-summary-row">
              <span className="cart-summary-label">상품 수</span>
              <span className="cart-summary-value">{totalItems}개</span>
            </div>
            <div className="cart-summary-row">
              <span className="cart-summary-label">상품 금액</span>
              <span className="cart-summary-value">{formatPrice(total)}</span>
            </div>
            <div className="cart-summary-row">
              <span className="cart-summary-label">배송비</span>
              <span className="cart-summary-value">무료</span>
            </div>
            <div className="cart-summary-row total">
              <span className="cart-summary-label">총 결제금액</span>
              <span className="cart-summary-value">{formatPrice(total)}</span>
            </div>
            <button
              className="btn btn-primary btn-lg"
              onClick={handleOrder}
              disabled={ordering}
            >
              {ordering ? '주문 처리 중...' : '주문하기'}
            </button>
          </div>
        </div>
      </div>

      {toast && (
        <div className="toast-container">
          <div className={`toast toast-${toast.type}`}>{toast.message}</div>
        </div>
      )}
    </>
  );
}

export default CartPage;
