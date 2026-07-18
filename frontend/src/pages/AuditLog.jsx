import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import api from "../api.js";

const ACTION_LABELS = {
  LOGIN_SUCCESS: { label: "Login", cls: "ok" },
  LOGIN_FAILURE: { label: "Login failed", cls: "bad" },
  LIST_PATIENTS: { label: "List", cls: "" },
  SEARCH_PATIENTS: { label: "Search", cls: "" },
  VIEW_PATIENT: { label: "View", cls: "" },
  CREATE_PATIENT: { label: "Create", cls: "ok" },
  UPDATE_PATIENT: { label: "Update", cls: "warn" },
  VIEW_AUDIT_LOG: { label: "Audit view", cls: "" },
};

export default function AuditLog() {
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [params] = useSearchParams();
  const patientFilter = params.get("patient");

  useEffect(() => {
    setLoading(true);
    api
      .get("/audit", { params: patientFilter ? { patient_id: patientFilter } : {} })
      .then(({ data }) => setLogs(data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load audit log."))
      .finally(() => setLoading(false));
  }, [patientFilter]);

  return (
    <div className="card">
      <h2>Audit Log</h2>
      <p className="muted small">
        Immutable, append-only record of every access to and change of PHI (HIPAA §164.312(b)).
        {patientFilter && <> Filtered to patient #{patientFilter}.</>}
      </p>
      {error && <div className="banner error">{error}</div>}
      {loading ? (
        <p className="muted">Loading…</p>
      ) : (
        <table className="data-table audit">
          <thead>
            <tr>
              <th>Time (UTC)</th>
              <th>User</th>
              <th>Action</th>
              <th>Patient</th>
              <th>Detail</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((l) => {
              const a = ACTION_LABELS[l.action] || { label: l.action, cls: "" };
              return (
                <tr key={l.id}>
                  <td className="nowrap">{new Date(l.timestamp).toLocaleString()}</td>
                  <td>{l.username}</td>
                  <td>
                    <span className={`tag tag-${a.cls}`}>{a.label}</span>
                  </td>
                  <td>{l.patient_id ?? "—"}</td>
                  <td className="detail">{l.detail}</td>
                  <td className="muted">{l.ip_address || "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
