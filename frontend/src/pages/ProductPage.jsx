import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { productsAPI, reviewsAPI } from '../api';
import { useAuth } from '../context/AuthContext';
import { useCart } from '../context/CartContext';
import StarRating from '../components/StarRating';
import ReviewList from '../components/ReviewList';
import ReviewForm from '../components/ReviewForm';

const categoryColors = {
  '전자기기': '#3498db',
  '패션': '#9b59b6',
  '식품': '#27ae60',
  '생활용품': '#f39c12',
  '뷰티': '#e74c3c',
};

function ProductPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const { addToCart } = useCart();

  const [product, setProduct] = useState(null);
  const [reviews, setReviews] = useState([]);
  const [loading, setLoading] = useState(true);
  const [quantity, setQuantity] = useState(1);
  const [addingToCart, setAddingToCart] = useState(false);
  const [toast, setToast] = useState(null);

  const fetchProduct = useCallback(async () => {
    try {
      const res = await productsAPI.getById(id);
      setProduct(res.data.product);
    } catch (err) {
      console.error('상품 조회 실패:', err);
    }
  }, [id]);

  const fetchReviews = useCallback(async () => {
    try {
      const res = await reviewsAPI.getByProduct(id);
      setReviews(res.data.reviews || []);
    } catch (err) {
      console.error('리뷰 조회 실패:', err);
    }
  }, [id]);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([fetchProduct(), fetchReviews()]);
      setLoading(false);
    };
    loadData();
  }, [fetchProduct, fetchReviews]);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  };

  const handleAddToCart = async () => {
    if (!user) {
      navigate('/login');
      return;
    }

    setAddingToCart(true);
    try {
      await addToCart(product.id, quantity);
      showToast('장바구니에 담았습니다');
    } catch (err) {
      showToast('장바구니 추가에 실패했습니다', 'error');
    } finally {
      setAddingToCart(false);
    }
  };

  const handleReviewAdded = () => {
    fetchReviews();
    showToast('리뷰가 등록되었습니다');
  };

  const formatPrice = (price) => {
    return price.toLocaleString('ko-KR') + '원';
  };

  const getAverageRating = () => {
    if (reviews.length === 0) return 0;
    const total = reviews.reduce((sum, r) => sum + r.rating, 0);
    return total / reviews.length;
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
      </div>
    );
  }

  if (!product) {
    return (
      <div className="container" style={{ padding: '60px 20px', textAlign: 'center' }}>
        <p style={{ fontSize: '1.2rem', color: '#999' }}>상품을 찾을 수 없습니다</p>
      </div>
    );
  }

  const averageRating = getAverageRating();

  return (
    <>
      <div className="product-detail">
        <div className="product-detail-top">
          <div className="product-detail-image">
            {product.imageUrl ? (
              <img
                src={product.imageUrl}
                alt={product.name}
                onError={(e) => {
                  e.target.style.display = 'none';
                  e.target.nextSibling.style.display = 'flex';
                }}
              />
            ) : null}
            <div
              className="product-detail-placeholder"
              style={{
                backgroundColor: categoryColors[product.category] || '#95a5a6',
                display: product.imageUrl ? 'none' : 'flex',
              }}
            >
              {product.name}
            </div>
          </div>

          <div className="product-detail-info">
            <span className="product-detail-category">{product.category}</span>
            <h1 className="product-detail-name">{product.name}</h1>

            {averageRating > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <StarRating rating={Math.round(averageRating)} size="1.2rem" />
                <span style={{ fontSize: '1rem', color: '#666' }}>
                  {averageRating.toFixed(1)} ({reviews.length}개 리뷰)
                </span>
              </div>
            )}

            <p className="product-detail-price">{formatPrice(product.price)}</p>

            {product.description && (
              <p className="product-detail-description">{product.description}</p>
            )}

            <p
              className={`product-detail-stock ${
                product.stock > 0 ? 'in-stock' : 'out-of-stock'
              }`}
            >
              {product.stock > 0
                ? `재고: ${product.stock}개 남음`
                : '품절'}
            </p>

            {product.stock > 0 && (
              <div className="product-detail-actions">
                <div className="quantity-selector">
                  <button
                    onClick={() => setQuantity(Math.max(1, quantity - 1))}
                    disabled={quantity <= 1}
                  >
                    -
                  </button>
                  <span>{quantity}</span>
                  <button
                    onClick={() =>
                      setQuantity(Math.min(product.stock, quantity + 1))
                    }
                    disabled={quantity >= product.stock}
                  >
                    +
                  </button>
                </div>
                <button
                  className="btn btn-primary btn-lg add-to-cart-btn"
                  onClick={handleAddToCart}
                  disabled={addingToCart}
                >
                  {addingToCart ? '담는 중...' : '장바구니 담기'}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="review-section">
        <h2 className="review-section-title">상품 리뷰</h2>
        {reviews.length > 0 && (
          <div className="review-average">
            <span className="review-average-number">{averageRating.toFixed(1)}</span>
            <StarRating rating={Math.round(averageRating)} size="1.3rem" />
            <span className="review-average-count">{reviews.length}개 리뷰</span>
          </div>
        )}

        <ReviewList reviews={reviews} />

        <div style={{ marginTop: '30px' }}>
          <ReviewForm productId={id} onReviewAdded={handleReviewAdded} />
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

export default ProductPage;
