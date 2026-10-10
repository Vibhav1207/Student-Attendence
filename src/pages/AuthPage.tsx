import { useEffect, useState } from "react";
import type { SubmitEvent } from "react";
import { AlertCircle, Eye, EyeOff } from "lucide-react";
import { api } from "../api";
import type { AuthResponse, ClassInfo } from "../types";
import universityLogo from "../assets/sanjivani-university-logo.png";
import "../styles/Auth.css";

type Mode = "login" | "signup";

type AuthPageProps = {
  onAuthenticated: (result: AuthResponse) => void;
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const AuthPage = ({ onAuthenticated }: AuthPageProps) => {
  const [mode, setMode] = useState<Mode>("login");

  return (
    <div className="auth-page">
      <aside className="auth-panel">
        <div className="auth-panel-center">
          <div className="auth-logo-card">
            <img src={universityLogo} alt="Sanjivani University" />
          </div>
          <h1 className="auth-product">Sanjivani Attendance Tracker</h1>
          <p className="auth-dept">Department of Computer Science &amp; Engineering</p>
        </div>
      </aside>

      <main className="auth-main">
        <div className="auth-card">
          <div className="auth-tabs" role="tablist">
            <button role="tab" aria-selected={mode === "login"} className={mode === "login" ? "active" : ""} onClick={() => setMode("login")}>
              Log in
            </button>
            <button role="tab" aria-selected={mode === "signup"} className={mode === "signup" ? "active" : ""} onClick={() => setMode("signup")}>
              Faculty sign up
            </button>
          </div>

          {mode === "login" ? (
            <LoginForm onAuthenticated={onAuthenticated} />
          ) : (
            <FacultySignupForm onAuthenticated={onAuthenticated} onSwitch={() => setMode("login")} />
          )}
        </div>
      </main>
    </div>
  );
};

/* =========================================
   LOGIN
========================================= */

function LoginForm({ onAuthenticated }: { onAuthenticated: (r: AuthResponse) => void }) {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");
    if (!identifier.trim() || !password) {
      setError("Enter your PRN or email and your password.");
      return;
    }
    setLoading(true);
    try {
      onAuthenticated(await api.login(identifier.trim(), password));
    } catch (err) {
      setError((err as Error).message);
      setLoading(false);
    }
  };

  return (
    <form className="auth-form" onSubmit={handleSubmit} noValidate>
      <div className="auth-heading">
        <h2>Log in</h2>
        <p>Students: use your PRN. Faculty: use your email.</p>
      </div>

      {error && <FormError message={error} />}

      <div className="form-group">
        <label htmlFor="identifier">PRN or email</label>
        <input
          id="identifier"
          value={identifier}
          onChange={(e) => setIdentifier(e.target.value)}
          autoComplete="username"
          placeholder="e.g. 2125UCEF1001"
          autoFocus
        />
      </div>

      <PasswordField id="password" label="Password" value={password} onChange={setPassword} autoComplete="current-password" />

      <button type="submit" className="primary-button auth-submit" disabled={loading}>
        {loading ? "Logging in…" : "Log in"}
      </button>

      <p className="auth-note">
        First time? Your starting password is with your class coordinator. Forgot it? Ask them to
        reset it.
      </p>
    </form>
  );
}

/* =========================================
   FACULTY SIGN UP
========================================= */

function FacultySignupForm({ onAuthenticated, onSwitch }: { onAuthenticated: (r: AuthResponse) => void; onSwitch: () => void }) {
  const [classes, setClasses] = useState<ClassInfo[]>([]);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const designation = "Class Coordinator";
  const [selected, setSelected] = useState<string[]>([]);
  const [facultyCode, setFacultyCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);



  useEffect(() => {
    api
      .classes()
      .then((d) => setClasses(d.classes))
      .catch((err: Error) => setError(`Couldn't load the class list. ${err.message}`));
  }, []);

  const toggle = (id: string) => setSelected([id]);   // single class (dropdown)

  const handleSubmit = async (e: SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    let problem = "";
    if (name.trim().length < 2) problem = "Enter your full name.";
    else if (!EMAIL_RE.test(email.trim())) problem = "Enter a valid email address.";
    else if (selected.length === 0) problem = "Choose the class you coordinate.";
    else if (!facultyCode.trim()) problem = "Enter the faculty access code from the department admin.";
    else if (password.length < 8) problem = "Password must be at least 8 characters.";
    else if (password !== confirm) problem = "Passwords don't match.";
    setError(problem);
    if (problem) return;

    setLoading(true);
    try {
      onAuthenticated(
        await api.signup({
          name: name.trim(),
          email: email.trim(),
          password,
          designation,
          facultyCode: facultyCode.trim(),
          classes: selected,
        })
      );
    } catch (err) {
      setError((err as Error).message);
      setLoading(false);
    }
  };

  return (
    <form className="auth-form" onSubmit={handleSubmit} noValidate>
      <div className="auth-heading">
        <h2>Faculty account</h2>
        <p>Student accounts are created by the department from the class lists.</p>
      </div>

      {error && <FormError message={error} />}

      <div className="form-group">
        <label htmlFor="name">Full name</label>
        <input id="name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
      </div>

      <div className="form-grid">
        <div className="form-group">
          <label htmlFor="email">College email</label>
          <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
        </div>
        <div className="form-group">
          <label>Role</label>
          <div className="role-label">Class Coordinator</div>
        </div>
      </div>

      <div className="form-group">
        <label htmlFor="classSelect">Class you coordinate</label>
        <select
          id="classSelect"
          value={selected[0] ?? ""}
          onChange={(e) => toggle(e.target.value)}
        >
          <option value="" disabled>Select class…</option>
          {classes.map((c) => (
            <option key={c.id} value={c.id}>
              {c.id}: {c.label}
            </option>
          ))}
        </select>
        {selected.length > 0 && (
          <p className="field-hint">{classes.find((c) => c.id === selected[0])?.label}</p>
        )}
      </div>

      <div className="form-group">
        <label htmlFor="facultyCode">Faculty access code</label>
        <input id="facultyCode" value={facultyCode} onChange={(e) => setFacultyCode(e.target.value)} autoComplete="off" />
      </div>

      <PasswordField id="new-password" label="Password" hint="At least 8 characters" value={password} onChange={setPassword} autoComplete="new-password" />
      <PasswordField id="confirm-password" label="Confirm password" value={confirm} onChange={setConfirm} autoComplete="new-password" />

      <button type="submit" className="primary-button auth-submit" disabled={loading}>
        {loading ? "Creating account…" : "Create faculty account"}
      </button>

      <p className="auth-switch">
        Already have an account?{" "}
        <button type="button" onClick={onSwitch}>
          Log in
        </button>
      </p>
    </form>
  );
}

/* =========================================
   SMALL PIECES
========================================= */

type PasswordFieldProps = {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete: string;
  hint?: string;
};

function PasswordField({ id, label, value, onChange, autoComplete, hint }: PasswordFieldProps) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="form-group">
      <label htmlFor={id}>{label}</label>
      <div className="password-input">
        <input id={id} type={visible ? "text" : "password"} value={value} onChange={(e) => onChange(e.target.value)} autoComplete={autoComplete} />
        <button type="button" onClick={() => setVisible((v) => !v)} aria-label={visible ? "Hide password" : "Show password"}>
          {visible ? <EyeOff size={17} /> : <Eye size={17} />}
        </button>
      </div>
      {hint && <p className="field-hint">{hint}</p>}
    </div>
  );
}

function FormError({ message }: { message: string }) {
  return (
    <div className="form-error" role="alert">
      <AlertCircle size={17} />
      {message}
    </div>
  );
}

export default AuthPage;
