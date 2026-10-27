import axios from 'axios';

const rawBaseUrl = import.meta.env.VITE_API_BASE_URL || '/api';
const baseURL = rawBaseUrl.endsWith('/api')
  ? rawBaseUrl
  : rawBaseUrl === '/'
  ? '/api'
  : `${rawBaseUrl.replace(/\/+$/, '')}/api`;

const api = axios.create({
  baseURL,
  timeout: 120000,
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const message = error.response?.data?.error?.message || error.message || 'An unexpected error occurred';
    return Promise.reject(new Error(message));
  }
);

const getHeaders = (ownerToken) => ({
  'x-owner-token': ownerToken,
});

export const uploadScan = async (file, ownerToken) => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('archive', file);
  const { data } = await api.post('/scans/upload', formData, {
    headers: {
      ...getHeaders(ownerToken),
      'Content-Type': 'multipart/form-data',
    },
  });
  return data;
};

export const githubScan = async (repoUrl, ownerToken) => {
  const { data } = await api.post('/scans/github', { repoUrl, repositoryUrl: repoUrl }, {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export const getScans = async (ownerToken) => {
  const { data } = await api.get('/scans', {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export const getScan = async (scanId, ownerToken) => {
  const { data } = await api.get(`/scans/${scanId}`, {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export const getScanFindings = async (scanId, ownerToken, filters = {}) => {
  const params = new URLSearchParams();
  if (filters.severity) params.append('severity', filters.severity);
  if (filters.category) params.append('category', filters.category);
  if (filters.status) params.append('status', filters.status);
  if (filters.search) params.append('search', filters.search);
  const { data } = await api.get(`/scans/${scanId}/findings?${params.toString()}`, {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export const getFinding = async (findingId, ownerToken) => {
  const { data } = await api.get(`/findings/${findingId}`, {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export const proposeFix = async (findingId, ownerToken) => {
  const { data } = await api.post(`/findings/${findingId}/propose-fix`, {}, {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export const updateFindingStatus = async (findingId, status, ownerToken) => {
  const { data } = await api.patch(`/findings/${findingId}/status`, { status }, {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export const deleteScan = async (scanId, ownerToken) => {
  const { data } = await api.delete(`/scans/${scanId}`, {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export const exportScan = async (scanId, ownerToken) => {
  const { data } = await api.get(`/scans/${scanId}/export`, {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export const rescan = async (scanId, ownerToken) => {
  const { data } = await api.post(`/scans/${scanId}/rescan`, {}, {
    headers: getHeaders(ownerToken),
  });
  return data;
};

export default api;
