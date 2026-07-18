import { useEffect, useState } from "react";
import { Link, useParams, useNavigate } from "react-router-dom";
import api from "../api.js";
import { useAuth } from "../auth.jsx";

function Field({ label, value }) {
  return (
    <div className="field">
      <div className="field-label">{label}</div>
      <div className="field-value">{value || <span className="muted">—</span>}</div>
    </div>
  );
}

export default function PatientView() {
  const { id } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [patient, setPatient] = useState(null);
  const [error, setError] = useState("");
  const [reveal, setReveal] = useState(false);

  useEffect(() => {
    api
      .get(`/patients/${id}`)
      .then(({ data }) => setPatient(data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load patient."));
  }, [id]);

  if (error) return <div className="card banner error">{error}</div>;
  if (!patient) return <div className="card muted">Loading…</div>;

  const mask = (v) => (v ? "•••-••-" + v.slice(-4) : "—");

  return (
    <div className="card">
      <div className="row between center-v">
        <div>
          <h2>
            {patient.first_name} {patient.last_name}
          </h2>
          <div className="muted">
            MRN <code>{patient.mrn}</code> · DOB {patient.date_of_birth}
          </div>
        </div>
        <div className="row gap">
          <Link to={`/patients/${id}/edit`} className="btn-primary">
            Edit
          </Link>
          <button className="btn-ghost" onClick={() => navigate("/patients")}>
            Back
          </button>
        </div>
      </div>

      <div className="phi-banner">
        Viewing protected health information — this access has been recorded in the audit log.
      </div>

      <div className="section-title">Contact</div>
      <div className="field-grid">
        <Field label="Phone" value={patient.phone} />
        <Field label="Email" value={patient.email} />
        <Field label="Address" value={patient.address} />
      </div>

      <div className="section-title">
        Sensitive identifiers
        <button className="btn-ghost tiny" onClick={() => setReveal((r) => !r)}>
          {reveal ? "Hide" : "Reveal"}
        </button>
      </div>
      <div className="field-grid">
        <Field label="SSN" value={reveal ? patient.ssn : mask(patient.ssn)} />
        <Field label="Insurance provider" value={patient.insurance_provider} />
        <Field
          label="Insurance ID"
          value={reveal ? patient.insurance_id : patient.insurance_id ? "••••••" : "—"}
        />
      </div>

      <div className="section-title">Clinical notes</div>
      <div className="notes-box">
        {patient.clinical_notes || <span className="muted">No notes recorded.</span>}
      </div>

      <div className="meta-row muted small">
        Created {new Date(patient.created_at).toLocaleString()} · Updated{" "}
        {new Date(patient.updated_at).toLocaleString()}
        {user?.role === "admin" && (
          <>
            {" · "}
            <Link to={`/audit?patient=${patient.id}`}>View access history →</Link>
          </>
        )}
      </div>
    </div>
  );
}
