import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import api from "../api.js";

const EMPTY = {
  first_name: "",
  last_name: "",
  date_of_birth: "",
  ssn: "",
  phone: "",
  email: "",
  address: "",
  insurance_provider: "",
  insurance_id: "",
  clinical_notes: "",
};

export default function PatientForm({ mode }) {
  const { id } = useParams();
  const navigate = useNavigate();
  const isEdit = mode === "edit";
  const [form, setForm] = useState(EMPTY);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(isEdit);

  useEffect(() => {
    if (!isEdit) return;
    api
      .get(`/patients/${id}`)
      .then(({ data }) => {
        // Null values come back from the API as null; normalize to "" for inputs.
        const filled = { ...EMPTY };
        for (const k of Object.keys(EMPTY)) filled[k] = data[k] ?? "";
        setForm(filled);
      })
      .catch((err) => setError(err.response?.data?.detail || "Failed to load patient."))
      .finally(() => setLoading(false));
  }, [id, isEdit]);

  function update(k, v) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  // Convert "" back to null so we don't store empty strings for optional PHI.
  function normalize(payload) {
    const out = {};
    for (const [k, v] of Object.entries(payload)) out[k] = v === "" ? null : v;
    return out;
  }

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const body = normalize(form);
      if (isEdit) {
        const { data } = await api.put(`/patients/${id}`, body);
        navigate(`/patients/${data.id}`);
      } else {
        const { data } = await api.post("/patients", body);
        navigate(`/patients/${data.id}`);
      }
    } catch (err) {
      const detail = err.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "Save failed. Check the required fields.");
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <div className="card muted">Loading…</div>;

  return (
    <div className="card">
      <h2>{isEdit ? "Edit Patient" : "New Patient"}</h2>
      {error && <div className="banner error">{error}</div>}
      <form onSubmit={onSubmit}>
        <div className="section-title">Identity</div>
        <div className="form-grid">
          <label>
            First name *
            <input
              required
              value={form.first_name}
              onChange={(e) => update("first_name", e.target.value)}
            />
          </label>
          <label>
            Last name *
            <input
              required
              value={form.last_name}
              onChange={(e) => update("last_name", e.target.value)}
            />
          </label>
          <label>
            Date of birth *
            <input
              required
              type="date"
              value={form.date_of_birth}
              onChange={(e) => update("date_of_birth", e.target.value)}
            />
          </label>
          <label>
            SSN
            <input
              placeholder="123-45-6789"
              value={form.ssn}
              onChange={(e) => update("ssn", e.target.value)}
            />
          </label>
        </div>

        <div className="section-title">Contact</div>
        <div className="form-grid">
          <label>
            Phone
            <input value={form.phone} onChange={(e) => update("phone", e.target.value)} />
          </label>
          <label>
            Email
            <input
              type="email"
              value={form.email}
              onChange={(e) => update("email", e.target.value)}
            />
          </label>
          <label className="span-2">
            Address
            <input value={form.address} onChange={(e) => update("address", e.target.value)} />
          </label>
        </div>

        <div className="section-title">Insurance</div>
        <div className="form-grid">
          <label>
            Provider
            <input
              value={form.insurance_provider}
              onChange={(e) => update("insurance_provider", e.target.value)}
            />
          </label>
          <label>
            Member ID
            <input
              value={form.insurance_id}
              onChange={(e) => update("insurance_id", e.target.value)}
            />
          </label>
        </div>

        <div className="section-title">Clinical notes</div>
        <textarea
          rows={5}
          value={form.clinical_notes}
          onChange={(e) => update("clinical_notes", e.target.value)}
        />

        <div className="row gap end">
          <button type="button" className="btn-ghost" onClick={() => navigate(-1)}>
            Cancel
          </button>
          <button className="btn-primary" disabled={busy}>
            {busy ? "Saving…" : isEdit ? "Save Changes" : "Create Patient"}
          </button>
        </div>
      </form>
    </div>
  );
}
