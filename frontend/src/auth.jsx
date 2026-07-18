import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import api, { getToken, setToken, preauthConfig } from "./api.js";

const AuthContext = createContext(null);

// HIPAA §164.312(a)(2)(iii) automatic logoff — sign the user out after this much
// inactivity, independent of the token's absolute lifetime.
const IDLE_LIMIT_MS = 10 * 60 * 1000;

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function bootstrap() {
      if (!getToken()) {
        setLoading(false);
        return;
      }
      try {
        const { data } = await api.get("/auth/me");
        setUser(data);
      } catch {
        setToken(null);
      } finally {
        setLoading(false);
      }
    }
    bootstrap();
  }, []);

  // Step 1: password. Returns { enrolled, preauth_token } — MFA still required.
  async function login(username, password) {
    const { data } = await api.post("/auth/login", { username, password });
    return data;
  }

  // Step 2a: verify TOTP for an enrolled user → full session.
  async function mfaVerify(preauthToken, code) {
    const { data } = await api.post("/auth/mfa/verify", { code }, preauthConfig(preauthToken));
    await establishSession(data.access_token);
  }

  // Step 2b (enrollment): fetch secret + QR, then verify to activate MFA.
  async function mfaEnrollStart(preauthToken) {
    const { data } = await api.post("/auth/mfa/enroll", {}, preauthConfig(preauthToken));
    return data; // { secret, otpauth_uri, qr_data_uri }
  }
  async function mfaEnrollVerify(preauthToken, code) {
    const { data } = await api.post(
      "/auth/mfa/enroll/verify",
      { code },
      preauthConfig(preauthToken)
    );
    await establishSession(data.access_token);
  }

  async function establishSession(accessToken) {
    setToken(accessToken);
    const me = await api.get("/auth/me");
    setUser(me.data);
  }

  async function logout() {
    try {
      await api.post("/auth/logout");
    } catch {
      // best-effort server-side revocation; clear locally regardless
    }
    setToken(null);
    setUser(null);
  }

  // Idle auto-logout: reset a timer on user activity; fire logout when it lapses.
  const idleTimer = useRef(null);
  useEffect(() => {
    if (!user) return;
    const events = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    const reset = () => {
      clearTimeout(idleTimer.current);
      idleTimer.current = setTimeout(async () => {
        await logout();
        window.location.assign("/login?idle=1");
      }, IDLE_LIMIT_MS);
    };
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => {
      clearTimeout(idleTimer.current);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [user]);

  const value = useMemo(
    () => ({ user, loading, login, mfaVerify, mfaEnrollStart, mfaEnrollVerify, logout }),
    [user, loading]
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
