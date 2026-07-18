import axios from "axios";

// Session token is kept in memory + sessionStorage (cleared when the tab closes)
// rather than localStorage — reduces PHI-session exposure on shared workstations.
const TOKEN_KEY = "hipaa_demo_token";

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}
export function setToken(token) {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

const api = axios.create({ baseURL: "/api" });

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Global handler: on 401 (expired/invalid session) clear token and bounce to login.
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401) {
      setToken(null);
      if (window.location.pathname !== "/login") {
        window.location.assign("/login?expired=1");
      }
    }
    return Promise.reject(err);
  }
);

export default api;
