// TGAM-SOC Central API Client
// Connects to backend FastAPI server using Bearer Token Authentication

const DEFAULT_BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_SOC_API_URL) || 'http://localhost:8000';
const DEFAULT_TOKEN = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_SOC_API_TOKEN) || 'dev-token-123';

export const getApiConfig = () => {
  const baseUrl = localStorage.getItem('tgam_soc_api_base') || DEFAULT_BASE_URL;
  const token = localStorage.getItem('tgam_soc_api_token') || DEFAULT_TOKEN;
  return { baseUrl: baseUrl.replace(/\/+$/, ''), token };
};

export const setApiConfig = (baseUrl, token) => {
  if (baseUrl) localStorage.setItem('tgam_soc_api_base', baseUrl.trim().replace(/\/+$/, ''));
  if (token) localStorage.setItem('tgam_soc_api_token', token.trim());
};

export const resetApiConfig = () => {
  localStorage.removeItem('tgam_soc_api_base');
  localStorage.removeItem('tgam_soc_api_token');
};

class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

async function request(endpoint, options = {}) {
  const { baseUrl, token } = getApiConfig();
  const url = `${baseUrl}${endpoint}`;

  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...options.headers,
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), options.timeout || 12000);

    const response = await fetch(url, {
      ...options,
      headers,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (response.status === 401) {
      throw new ApiError('Unauthorized: Invalid or missing API Bearer token.', 401);
    }

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      let errorDetail = `HTTP ${response.status} ${response.statusText}`;
      try {
        const errorJson = await response.json();
        if (errorJson && errorJson.detail) {
          errorDetail = errorJson.detail;
        }
      } catch {
        // use default error detail
      }
      throw new ApiError(errorDetail, response.status);
    }

    return await response.json();
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err.name === 'AbortError') {
      throw new ApiError('Request timed out while connecting to SOC backend.', 408);
    }
    throw new ApiError(
      `Cannot connect to SOC backend at ${baseUrl}. Ensure backend is running. (${err.message})`,
      0
    );
  }
}

export const api = {
  // Test connectivity
  async testConnection() {
    return await request('/api/v1/incidents', { timeout: 5000 });
  },

  // Incident endpoints
  async getIncidents() {
    const res = await request('/api/v1/incidents');
    return res || [];
  },

  async getIncident(incidentId) {
    return await request(`/api/v1/incidents/${encodeURIComponent(incidentId)}`);
  },

  async getIncidentEvidence(incidentId) {
    const res = await request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/evidence`);
    return res || [];
  },

  async getIncidentEntities(incidentId) {
    const res = await request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/entities`);
    return res || [];
  },

  async getIncidentMitre(incidentId) {
    const res = await request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/mitre`);
    return res || [];
  },

  async getIncidentAssessment(incidentId) {
    return await request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/assessment`);
  },

  async getIncidentAnalysis(incidentId) {
    return await request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/analysis`);
  },

  async getIncidentDecision(incidentId) {
    return await request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/decision`);
  },

  async getIncidentHistory(incidentId) {
    return await request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/history`);
  },

  // Governance override endpoint is documented as 501 Not Implemented by backend architecture.
  // We expose this helper solely to test/verify the backend's 501 rejection policy.
  async submitOverrideAttempt(incidentId, action, reason) {
    return await request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/governance/override`, {
      method: 'POST',
      body: JSON.stringify({ action, reason }),
    });
  }
};
