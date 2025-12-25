import axios from 'axios';

const API_BASE_URL = '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken,
          });

          const { access_token, refresh_token } = response.data;
          localStorage.setItem('access_token', access_token);
          localStorage.setItem('refresh_token', refresh_token);

          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return api(originalRequest);
        }
      } catch {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/login';
      }
    }

    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  login: (username: string, password: string) =>
    api.post('/auth/login', new URLSearchParams({ username, password }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }),
  register: (data: { email: string; username: string; password: string; full_name?: string }) =>
    api.post('/auth/register', data),
  me: () => api.get('/auth/me'),
  logout: () => api.post('/auth/logout'),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    }),
};

// URL Scanning API
export const urlAPI = {
  scan: (url: string) => api.post('/urls/scan', { url }),
  scanBatch: (urls: string[]) => api.post('/urls/scan/batch', { urls }),
  getScans: (params?: {
    page?: number;
    page_size?: number;
    is_phishing?: boolean;
    severity?: string;
    search?: string;
  }) => api.get('/urls/scans', { params }),
  getScan: (id: number) => api.get(`/urls/scans/${id}`),
  updateStatus: (id: number, status: string) =>
    api.patch(`/urls/scans/${id}/status`, null, { params: { new_status: status } }),
  getStats: (days?: number) => api.get('/urls/stats', { params: { days } }),
};

// Threat Intelligence API
export const threatAPI = {
  getIntel: (params?: {
    page?: number;
    page_size?: number;
    indicator_type?: string;
    severity?: string;
  }) => api.get('/threats/intel', { params }),
  addIntel: (data: {
    indicator: string;
    indicator_type: string;
    threat_type?: string;
    severity?: string;
    description?: string;
  }) => api.post('/threats/intel', data),
  deleteIntel: (id: number) => api.delete(`/threats/intel/${id}`),
  syncIntel: () => api.post('/threats/intel/sync'),
  getStats: () => api.get('/threats/intel/stats'),
  checkIndicator: (indicator: string) =>
    api.post('/threats/check', null, { params: { indicator } }),
  getTopBlocked: (limit?: number, days?: number) =>
    api.get('/threats/top-blocked', { params: { limit, days } }),
};

// Network Monitoring API
export const networkAPI = {
  getConnections: (params?: {
    page?: number;
    page_size?: number;
    is_blocked?: boolean;
    protocol?: string;
  }) => api.get('/network/connections', { params }),
  getStats: (hours?: number) => api.get('/network/stats', { params: { hours } }),
  getRealTime: () => api.get('/network/real-time'),
  blockIP: (ip: string, reason?: string) =>
    api.post(`/network/block/${ip}`, null, { params: { reason } }),
  unblockIP: (ip: string) => api.post(`/network/unblock/${ip}`),
  getBlocked: () => api.get('/network/blocked'),
  getProtocols: (hours?: number) => api.get('/network/protocols', { params: { hours } }),
  getTopDestinations: (limit?: number, hours?: number) =>
    api.get('/network/top-destinations', { params: { limit, hours } }),
  getBandwidth: (hours?: number) => api.get('/network/bandwidth', { params: { hours } }),
};

// Dashboard API
export const dashboardAPI = {
  getStats: (days?: number) => api.get('/dashboard/stats', { params: { days } }),
  getSeverityDistribution: (days?: number) =>
    api.get('/dashboard/severity-distribution', { params: { days } }),
  getTrends: (days?: number) => api.get('/dashboard/trends', { params: { days } }),
  getRecentThreats: (limit?: number) =>
    api.get('/dashboard/recent-threats', { params: { limit } }),
  getTopBlocked: (limit?: number, days?: number) =>
    api.get('/dashboard/top-blocked-domains', { params: { limit, days } }),
  getTimeline: (hours?: number) =>
    api.get('/dashboard/activity-timeline', { params: { hours } }),
  getHealth: () => api.get('/dashboard/system-health'),
  getSummary: () => api.get('/dashboard/summary'),
};

// Alerts API
export const alertsAPI = {
  getAlerts: (params?: {
    page?: number;
    page_size?: number;
    severity?: string;
    is_read?: boolean;
    is_acknowledged?: boolean;
  }) => api.get('/alerts/', { params }),
  getUnread: (limit?: number) => api.get('/alerts/unread', { params: { limit } }),
  getCount: () => api.get('/alerts/count'),
  getAlert: (id: number) => api.get(`/alerts/${id}`),
  updateAlert: (id: number, data: { is_read?: boolean; is_acknowledged?: boolean }) =>
    api.patch(`/alerts/${id}`, data),
  markAllRead: () => api.post('/alerts/mark-all-read'),
  acknowledgeAll: (severity?: string) =>
    api.post('/alerts/acknowledge-all', null, { params: { severity } }),
  deleteAlert: (id: number) => api.delete(`/alerts/${id}`),
  getTimeline: (days?: number) => api.get('/alerts/stats/timeline', { params: { days } }),
};

// Users API
export const usersAPI = {
  getUsers: (params?: { page?: number; role?: string; search?: string }) =>
    api.get('/users/', { params }),
  getUser: (id: number) => api.get(`/users/${id}`),
  createUser: (data: {
    email: string;
    username: string;
    password: string;
    full_name?: string;
  }) => api.post('/users/', data),
  updateUser: (id: number, data: { email?: string; full_name?: string; role?: string; is_active?: boolean }) =>
    api.patch(`/users/${id}`, data),
  deleteUser: (id: number) => api.delete(`/users/${id}`),
  resetPassword: (id: number, newPassword: string) =>
    api.post(`/users/${id}/reset-password`, null, { params: { new_password: newPassword } }),
  getStats: () => api.get('/users/stats/summary'),
};

export default api;
