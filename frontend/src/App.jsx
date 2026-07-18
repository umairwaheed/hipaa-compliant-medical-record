import { Navigate, Link, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./auth.jsx";
import Login from "./pages/Login.jsx";
import PatientList from "./pages/PatientList.jsx";
import PatientForm from "./pages/PatientForm.jsx";
import PatientView from "./pages/PatientView.jsx";
import AuditLog from "./pages/AuditLog.jsx";

function ProtectedRoute({ children, adminOnly = false }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="center muted">Loading…</div>;
  if (!user) return <Navigate to="/login" state={{ from: location }} replace />;
  if (adminOnly && user.role !== "admin") return <Navigate to="/patients" replace />;
  return children;
}

function TopBar() {
  const { user, logout } = useAuth();
  if (!user) return null;
  return (
    <header className="topbar">
      <div className="brand">
        <span className="lock">🔒</span> HIPAA Record Manager
      </div>
      <nav>
        <Link to="/patients">Patients</Link>
        {user.role === "admin" && <Link to="/audit">Audit Log</Link>}
      </nav>
      <div className="user-box">
        <span className="whoami">
          {user.full_name} <span className={`role role-${user.role}`}>{user.role}</span>
        </span>
        <button className="btn-ghost" onClick={logout}>
          Sign out
        </button>
      </div>
    </header>
  );
}

export default function App() {
  return (
    <div className="app">
      <TopBar />
      <main className="content">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/patients"
            element={
              <ProtectedRoute>
                <PatientList />
              </ProtectedRoute>
            }
          />
          <Route
            path="/patients/new"
            element={
              <ProtectedRoute>
                <PatientForm mode="create" />
              </ProtectedRoute>
            }
          />
          <Route
            path="/patients/:id"
            element={
              <ProtectedRoute>
                <PatientView />
              </ProtectedRoute>
            }
          />
          <Route
            path="/patients/:id/edit"
            element={
              <ProtectedRoute>
                <PatientForm mode="edit" />
              </ProtectedRoute>
            }
          />
          <Route
            path="/audit"
            element={
              <ProtectedRoute adminOnly>
                <AuditLog />
              </ProtectedRoute>
            }
          />
          <Route path="*" element={<Navigate to="/patients" replace />} />
        </Routes>
      </main>
      <footer className="footer">
        Protected health information · Authorized access only · All activity is audited
      </footer>
    </div>
  );
}
