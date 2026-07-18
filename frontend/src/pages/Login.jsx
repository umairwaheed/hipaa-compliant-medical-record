import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../auth.jsx";

export default function Login() {
  const { login, mfaVerify, mfaEnrollStart, mfaEnrollVerify } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [stage, setStage] = useState("password"); // password | mfa | enroll
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [preauth, setPreauth] = useState(null);
  const [enroll, setEnroll] = useState(null); // { secret, qr_data_uri }
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const params = new URLSearchParams(location.search);
  const expired = params.get("expired");
  const idle = params.get("idle");

  async function submitPassword(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const res = await login(username, password);
      setPreauth(res.preauth_token);
      if (res.enrolled) {
        setStage("mfa");
      } else {
        const data = await mfaEnrollStart(res.preauth_token);
        setEnroll(data);
        setStage("enroll");
      }
    } catch (err) {
      setError(err.response?.data?.detail || "Sign in failed.");
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (stage === "mfa") await mfaVerify(preauth, code);
      else await mfaEnrollVerify(preauth, code);
      navigate("/patients", { replace: true });
    } catch (err) {
      setError(err.response?.data?.detail || "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <div className="card login-card">
        <h1>
          <span className="lock">🔒</span> Secure Sign In
        </h1>
        <p className="muted small">
          Access to protected health information is restricted to authorized users and requires
          multi-factor authentication. All activity is logged.
        </p>

        {expired && <div className="banner warn">Your session expired. Please sign in again.</div>}
        {idle && (
          <div className="banner warn">Signed out due to inactivity. Please sign in again.</div>
        )}
        {error && <div className="banner error">{error}</div>}

        {stage === "password" && (
          <form onSubmit={submitPassword}>
            <label>
              Username
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
                autoComplete="username"
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </label>
            <button className="btn-primary" disabled={busy}>
              {busy ? "Checking…" : "Continue"}
            </button>
          </form>
        )}

        {stage === "enroll" && enroll && (
          <form onSubmit={submitCode}>
            <div className="section-title">Set up authenticator</div>
            <p className="muted small">
              Scan this QR code with an authenticator app (Google Authenticator, Authy, 1Password),
              then enter the 6-digit code to finish enrollment.
            </p>
            <div className="qr-wrap">
              <img src={enroll.qr_data_uri} alt="MFA QR code" width={180} height={180} />
            </div>
            <p className="muted small">
              Can't scan? Enter this secret manually: <code>{enroll.secret}</code>
            </p>
            <label>
              Authentication code
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                autoFocus
              />
            </label>
            <button className="btn-primary" disabled={busy}>
              {busy ? "Verifying…" : "Enable MFA & Sign In"}
            </button>
          </form>
        )}

        {stage === "mfa" && (
          <form onSubmit={submitCode}>
            <div className="section-title">Two-factor authentication</div>
            <p className="muted small">Enter the 6-digit code from your authenticator app.</p>
            <label>
              Authentication code
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                autoFocus
              />
            </label>
            <button className="btn-primary" disabled={busy}>
              {busy ? "Verifying…" : "Verify & Sign In"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
