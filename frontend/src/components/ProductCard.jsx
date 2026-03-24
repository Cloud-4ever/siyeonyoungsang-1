import { useNavigate } from 'react-router-dom';
import StarRating from './StarRating';

const categoryColors = {
  '전자기기': '#3498db',
  '패션': '#9b59b6',
  '식품': '#27ae60',
  '생활용품': '#f39c12',
  '뷰티': '#e74c3c',
};

const productIcons = {
  '삼성 갤럭시 S24 울트라': '📱',
  'LG 그램 17인치 노트북': '💻',
  '애플 에어팟 프로 2세대': '🎧',
  'LG 스탠바이미 27인치': '🖥️',
  '나이키 에어맥스 97 - 화이트': '👟',
  '유니클로 히트텍 울트라 웜 세트': '🧥',
  '캉골 버킷햇 클래식': '👒',
  '노스페이스 눕시 패딩 자켓': '🧶',
  '곰곰 유기농 현미 10kg': '🌾',
  '정관장 홍삼정 에브리타임 30포': '🧧',
  '비비고 왕교자 만두 1.4kg': '🥟',
  '스타벅스 캡슐 커피 믹스 60개입': '☕',
  '다이슨 V15 무선 청소기': '🧹',
  '쿠쿠 IH 전기압력밥솥 10인용': '🍚',
  '코웨이 아이콘 정수기 렌탈': '💧',
  '일룸 데스커 모션 데스크': '🪑',
  '설화수 자음생 크림 60ml': '✨',
  '이니스프리 그린티 세럼 80ml': '🍵',
  '라네즈 립 슬리핑 마스크 20g': '💋',
  '에스티로더 더블웨어 파운데이션': '💄',
};

function ProductCard({ product }) {
  const navigate = useNavigate();

  const formatPrice = (price) => {
    return price.toLocaleString('ko-KR') + '원';
  };

  const getPlaceholderColor = (category) => {
    return categoryColors[category] || '#95a5a6';
  };

  const handleClick = () => {
    navigate(`/product/${product.id}`);
  };

  return (
    <div className="product-card" onClick={handleClick}>
      <div className="product-card-image">
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
          className="product-card-placeholder"
          style={{
            backgroundColor: getPlaceholderColor(product.category),
            display: product.imageUrl ? 'none' : 'flex',
          }}
        >
          <span style={{ fontSize: '3rem' }}>{productIcons[product.name] || '📦'}</span>
        </div>
      </div>
      <div className="product-card-info">
        {product.category && (
          <span className="product-card-category">{product.category}</span>
        )}
        <h3 className="product-card-name">{product.name}</h3>
        <p className="product-card-price">{formatPrice(product.price)}</p>
        {product.averageRating !== undefined && product.averageRating > 0 && (
          <div className="product-card-rating">
            <StarRating rating={Math.round(product.averageRating)} size="0.85rem" />
            <span style={{ color: '#999', fontSize: '0.8rem' }}>
              ({product.averageRating.toFixed(1)})
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

export default ProductCard;
