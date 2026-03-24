import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
});

// Request interceptor: attach Authorization header
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: handle 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('token');
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  signup: (data) => api.post('/api/auth/signup', data),
  login: (data) => api.post('/api/auth/login', data),
  getMe: () => api.get('/api/auth/me'),
};

// Products API
export const productsAPI = {
  getAll: (params) => api.get('/api/products', { params }),
  getById: (id) => api.get(`/api/products/${id}`),
};

// Reviews API
export const reviewsAPI = {
  getByProduct: (productId) => api.get(`/api/products/${productId}/reviews`),
  create: (productId, data) => api.post(`/api/products/${productId}/reviews`, data),
};

// Cart API
export const cartAPI = {
  getAll: () => api.get('/api/cart'),
  addItem: (data) => api.post('/api/cart', data),
  updateItem: (itemId, data) => api.put(`/api/cart/${itemId}`, data),
  removeItem: (itemId) => api.delete(`/api/cart/${itemId}`),
  clear: () => api.delete('/api/cart'),
};

// Orders API
export const ordersAPI = {
  create: () => api.post('/api/orders'),
  getAll: () => api.get('/api/orders'),
};

// Upload API
export const uploadAPI = {
  uploadFile: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/api/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
};

export default api;
