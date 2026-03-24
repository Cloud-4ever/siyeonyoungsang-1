import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { productsAPI } from '../api';
import ProductCard from '../components/ProductCard';

const categories = ['전체', '전자기기', '패션', '식품', '생활용품', '뷰티'];

function HomePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeCategory, setActiveCategory] = useState('전체');
  const [searchQuery, setSearchQuery] = useState(searchParams.get('search') || '');

  useEffect(() => {
    const search = searchParams.get('search') || '';
    setSearchQuery(search);
    fetchProducts(activeCategory, search);
  }, [searchParams]);

  const fetchProducts = async (category, search) => {
    setLoading(true);
    try {
      const params = {};
      if (category && category !== '전체') {
        params.category = category;
      }
      if (search) {
        params.search = search;
      }
      const res = await productsAPI.getAll(params);
      setProducts(res.data.products || []);
    } catch (err) {
      console.error('상품 조회 실패:', err);
      setProducts([]);
    } finally {
      setLoading(false);
    }
  };

  const handleCategoryChange = (category) => {
    setActiveCategory(category);
    fetchProducts(category, searchQuery);
  };

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      setSearchParams({ search: searchQuery.trim() });
    } else {
      setSearchParams({});
    }
    fetchProducts(activeCategory, searchQuery.trim());
  };

  return (
    <div className="container">
      <div className="category-filter">
        {categories.map((category) => (
          <button
            key={category}
            className={`category-btn ${activeCategory === category ? 'active' : ''}`}
            onClick={() => handleCategoryChange(category)}
          >
            {category}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="loading-container">
          <div className="spinner"></div>
        </div>
      ) : products.length === 0 ? (
        <div className="no-results">
          검색 결과가 없습니다
        </div>
      ) : (
        <div className="product-grid">
          {products.map((product) => (
            <ProductCard key={product.id} product={product} />
          ))}
        </div>
      )}
    </div>
  );
}

export default HomePage;
