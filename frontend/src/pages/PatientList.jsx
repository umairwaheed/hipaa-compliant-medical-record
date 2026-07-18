import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../api.js";

export default function PatientList() {
  const [patients, setPatients] = useState([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function load(q = "") {
    setLoading(true);
    setError("");
    try {
      const { data } = await api.get("/patients", { params: q ? { q } : {} });
      setPatients(data);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load patients.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  function onSearch(e) {
    e.preventDefault();
    load(query);
  }

  return (
    <div className="card">
      <div className="row between center-v">
        <h2>Patient Records</h2>
        <Link to="/patients/new" className="btn-primary">
          + New Patient
        </Link>
      </div>

      <form className="search-row" onSubmit={onSearch}>
        <input
          placeholder="Search by name, MRN, or date of birth…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button className="btn-secondary">Search</button>
        {query && (
          <button
            type="button"
            className="btn-ghost"
            onClick={() => {
              setQuery("");
              load();
            }}
          >
            Clear
          </button>
        )}
      </form>

      {error && <div className="banner error">{error}</div>}
      {loading ? (
        <p className="muted">Loading…</p>
      ) : patients.length === 0 ? (
        <p className="muted">No patient records found.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>MRN</th>
              <th>Last name</th>
              <th>First name</th>
              <th>Date of birth</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {patients.map((p) => (
              <tr key={p.id} className="clickable" onClick={() => navigate(`/patients/${p.id}`)}>
                <td><code>{p.mrn}</code></td>
                <td>{p.last_name}</td>
                <td>{p.first_name}</td>
                <td>{p.date_of_birth}</td>
                <td className="right">
                  <Link to={`/patients/${p.id}`} onClick={(e) => e.stopPropagation()}>
                    View →
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
