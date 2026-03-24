import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useCart } from '../context/CartContext';

function Navbar() {
  const [searchQuery, setSearchQuery] = useState('');
  const { user, logout } = useAuth();
  const { getCartCount } = useCart();
  const navigate = useNavigate();

  const cartCount = getCartCount();

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/?search=${encodeURIComponent(searchQuery.trim())}`);
    } else {
      navigate('/');
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <>
      <nav className="navbar">
        <div className="navbar-inner">
          <Link to="/" className="navbar-logo">
            ShopEasy
          </Link>

          <div className="navbar-search">
            <form onSubmit={handleSearch}>
              <input
                type="text"
                placeholder="상품을 검색해보세요"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              <button type="submit">검색</button>
            </form>
          </div>

          <div className="navbar-actions">
            <Link to="/cart" className="navbar-cart">
              <span className="navbar-cart-icon">🛒</span>
              {cartCount > 0 && <span className="cart-badge">{cartCount}</span>}
            </Link>

            {user ? (
              <div className="navbar-user">
                <Link to="/orders" className="navbar-user-name">
                  {user.name}님
                </Link>
                <button className="navbar-logout-btn" onClick={handleLogout}>
                  로그아웃
                </button>
              </div>
            ) : (
              <Link to="/login" className="navbar-login-btn">
                로그인
              </Link>
            )}
          </div>
        </div>
      </nav>

      <div className="mobile-search" style={{ marginTop: '70px' }}>
        <form onSubmit={handleSearch}>
          <input
            type="text"
            placeholder="상품을 검색해보세요"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          <button type="submit">검색</button>
        </form>
      </div>
    </>
  );
}

export default Navbar;
