import { useEffect, useState } from "react";
import api from "../api.js";
import { useAuth } from "../auth.jsx";

function StatusTag({ u }) {
  if (!u.is_active) return <span className="tag tag-bad">Inactive</span>;
  if (u.locked) return <span className="tag tag-warn">Locked</span>;
  return <span className="tag tag-ok">Active</span>;
}

export default function UserAdmin() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({
    username: "",
    full_name: "",
    role: "clinician",
    password: "",
  });
  const [resetFor, setResetFor] = useState(null); // user object
  const [newPw, setNewPw] = useState("");

  async function load() {
    setLoading(true);
    try {
      const { data } = await api.get("/users");
      setUsers(data);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load users.");
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function act(id, action) {
    setError("");
    try {
      await api.post(`/users/${id}/${action}`);
      await load();
    } catch (err) {
      setError(err.response?.data?.detail || "Action failed.");
    }
  }

  async function createUser(e) {
    e.preventDefault();
    setError("");
    setCreating(true);
    try {
      await api.post("/users", form);
      setForm({ username: "", full_name: "", role: "clinician", password: "" });
      await load();
    } catch (err) {
      const d = err.response?.data?.detail;
      setError(
        typeof d === "string" ? d : "Create failed — check the fields (password ≥12 chars, mixed)."
      );
    } finally {
      setCreating(false);
    }
  }

  async function submitReset(e) {
    e.preventDefault();
    setError("");
    try {
      await api.post(`/users/${resetFor.id}/reset-password`, { new_password: newPw });
      setResetFor(null);
      setNewPw("");
      await load();
    } catch (err) {
      const d = err.response?.data?.detail;
      setError(typeof d === "string" ? d : "Password reset failed (min 12 chars, mixed).");
    }
  }

  return (
    <div className="card">
      <h2>User Management</h2>
      <p className="muted small">
        Administer accounts: reset lost MFA, unlock, deactivate, and reset passwords. Every action
        is recorded in the audit log; MFA resets, deactivations, and password resets immediately
        revoke the user's active sessions.
      </p>
      {error && <div className="banner error">{error}</div>}

      <div className="section-title">Create user</div>
      <form className="form-grid" onSubmit={createUser}>
        <label>
          Username
          <input
            required
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
          />
        </label>
        <label>
          Full name
          <input
            required
            value={form.full_name}
            onChange={(e) => setForm({ ...form, full_name: e.target.value })}
          />
        </label>
        <label>
          Role
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="clinician">Clinician</option>
            <option value="admin">Administrator</option>
          </select>
        </label>
        <label>
          Temporary password
          <input
            type="password"
            required
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            placeholder="≥12 chars, mixed"
          />
        </label>
        <div className="span-2 right">
          <button className="btn-primary" disabled={creating}>
            {creating ? "Creating…" : "Create user"}
          </button>
        </div>
      </form>

      <div className="section-title">Accounts</div>
      {loading ? (
        <p className="muted">Loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Name</th>
              <th>Role</th>
              <th>MFA</th>
              <th>Status</th>
              <th>Failed</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>
                  <code>{u.username}</code>
                  {u.id === me.id && <span className="muted small"> (you)</span>}
                </td>
                <td>{u.full_name}</td>
                <td>
                  <span className={`role role-${u.role}`}>{u.role}</span>
                </td>
                <td>
                  {u.mfa_enabled ? (
                    <span className="tag tag-ok">On</span>
                  ) : (
                    <span className="tag">Off</span>
                  )}
                </td>
                <td>
                  <StatusTag u={u} />
                </td>
                <td>{u.failed_login_count}</td>
                <td className="actions-cell">
                  <button className="btn-ghost tiny" onClick={() => act(u.id, "reset-mfa")}>
                    Reset MFA
                  </button>
                  {u.locked && (
                    <button className="btn-ghost tiny" onClick={() => act(u.id, "unlock")}>
                      Unlock
                    </button>
                  )}
                  <button className="btn-ghost tiny" onClick={() => setResetFor(u)}>
                    Reset PW
                  </button>
                  {u.is_active ? (
                    <button
                      className="btn-ghost tiny"
                      disabled={u.id === me.id}
                      onClick={() => act(u.id, "deactivate")}
                    >
                      Deactivate
                    </button>
                  ) : (
                    <button className="btn-ghost tiny" onClick={() => act(u.id, "activate")}>
                      Activate
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {resetFor && (
        <div className="modal-backdrop" onClick={() => setResetFor(null)}>
          <form className="modal" onClick={(e) => e.stopPropagation()} onSubmit={submitReset}>
            <h3>Reset password — {resetFor.username}</h3>
            <p className="muted small">
              Sets a new temporary password and signs the user out everywhere.
            </p>
            <input
              type="password"
              autoFocus
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              placeholder="New password (≥12 chars, mixed)"
            />
            <div className="row gap end">
              <button type="button" className="btn-ghost" onClick={() => setResetFor(null)}>
                Cancel
              </button>
              <button className="btn-primary">Reset password</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
