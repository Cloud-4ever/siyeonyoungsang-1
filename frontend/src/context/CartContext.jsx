import { createContext, useState, useEffect, useContext, useCallback } from 'react';
import { cartAPI } from '../api';
import { useAuth } from './AuthContext';

const CartContext = createContext(null);

export function CartProvider({ children }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const { user } = useAuth();

  const fetchCart = useCallback(async () => {
    if (!user) {
      setItems([]);
      return;
    }
    setLoading(true);
    try {
      const res = await cartAPI.getAll();
      setItems(res.data.items || []);
    } catch (err) {
      console.error('장바구니 조회 실패:', err);
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    if (user) {
      fetchCart();
    } else {
      setItems([]);
    }
  }, [user, fetchCart]);

  const addToCart = async (productId, quantity = 1) => {
    try {
      await cartAPI.addItem({ productId, quantity });
      await fetchCart();
    } catch (err) {
      console.error('장바구니 추가 실패:', err);
      throw err;
    }
  };

  const updateQuantity = async (itemId, quantity) => {
    try {
      await cartAPI.updateItem(itemId, { quantity });
      await fetchCart();
    } catch (err) {
      console.error('수량 변경 실패:', err);
      throw err;
    }
  };

  const removeItem = async (itemId) => {
    try {
      await cartAPI.removeItem(itemId);
      await fetchCart();
    } catch (err) {
      console.error('아이템 삭제 실패:', err);
      throw err;
    }
  };

  const clearCart = async () => {
    try {
      await cartAPI.clear();
      setItems([]);
    } catch (err) {
      console.error('장바구니 비우기 실패:', err);
      throw err;
    }
  };

  const getCartCount = () => {
    return items.reduce((sum, item) => sum + item.quantity, 0);
  };

  const getCartTotal = () => {
    return items.reduce((sum, item) => sum + item.productPrice * item.quantity, 0);
  };

  return (
    <CartContext.Provider
      value={{
        items,
        loading,
        fetchCart,
        addToCart,
        updateQuantity,
        removeItem,
        clearCart,
        getCartCount,
        getCartTotal,
      }}
    >
      {children}
    </CartContext.Provider>
  );
}

export function useCart() {
  const context = useContext(CartContext);
  if (!context) {
    throw new Error('useCart는 CartProvider 내에서 사용해야 합니다');
  }
  return context;
}

export default CartContext;
