import axios from "axios";

// Session token in sessionStorage (cleared when the tab closes) rather than
// localStorage — reduces PHI-session exposure on shared workstations.
const TOKEN_KEY = "hipaa_token";

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}
export function setToken(token) {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

const api = axios.create({ baseURL: "/api" });

api.interceptors.request.use((config) => {
  // The full-session token is attached automatically. Pre-auth (MFA) calls pass
  // their own Authorization header and set `config.skipAuth` to opt out.
  const token = getToken();
  if (token && !config.skipAuth) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const url = err.config?.url || "";
    // Auth endpoints handle their own 401s (wrong password / wrong TOTP code);
    // don't hijack those into a redirect. Everywhere else, a 401 means the
    // session died → clear it and return to login.
    if (err.response?.status === 401 && !url.includes("/auth/")) {
      setToken(null);
      if (window.location.pathname !== "/login") {
        window.location.assign("/login?expired=1");
      }
    }
    return Promise.reject(err);
  }
);

// Helper for pre-auth (MFA-step) requests that carry the short-lived token.
export function preauthConfig(preauthToken) {
  return { skipAuth: true, headers: { Authorization: `Bearer ${preauthToken}` } };
}

export default api;
