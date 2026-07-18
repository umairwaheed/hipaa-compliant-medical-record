import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../auth.jsx";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const expired = new URLSearchParams(location.search).get("expired");

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await login(username, password);
      navigate("/patients", { replace: true });
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="card login-card" onSubmit={onSubmit}>
        <h1>
          <span className="lock">🔒</span> Secure Sign In
        </h1>
        <p className="muted small">
          Access to protected health information is restricted to authorized users. All
          activity is logged.
        </p>
        {expired && <div className="banner warn">Your session expired. Please sign in again.</div>}
        {error && <div className="banner error">{error}</div>}
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <button className="btn-primary" disabled={busy}>
          {busy ? "Signing in…" : "Sign In"}
        </button>
        <div className="demo-creds">
          <strong>Demo accounts</strong>
          <div>Admin — <code>admin</code> / <code>Admin123!</code></div>
          <div>Clinician — <code>dr.smith</code> / <code>Clinician123!</code></div>
        </div>
      </form>
    </div>
  );
}
