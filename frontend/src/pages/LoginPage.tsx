import React, { useState, useEffect, FormEvent } from 'react';
import { getJSON, postJSON, toErrorMessage } from '../lib/api';
import {
  generateRandomHex,
  deriveKeyFromPassword,
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  deriveAuthSecret,
  generatePaperRecoveryKey,
} from '../lib/crypto';
import { Bookmark, Lock, ShieldCheck, Key, ArrowRight, RefreshCw, AlertCircle } from 'lucide-react';

interface LoginPageProps {
  onLoginSuccess: (user: any, vaultKey: CryptoKey) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const [needsSetup, setNeedsSetup] = useState<boolean | null>(null);
  const [ssoConfig, setSSOConfig] = useState<{ enabled: boolean; issuerUrl: string } | null>(null);
  const [viewMode, setViewMode] = useState<'login' | 'setup' | 'recovery'>('login');

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [recoverySecret, setRecoverySecret] = useState('');

  const [generatedPaperKey, setGeneratedPaperKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    getJSON<{ needsSetup: boolean }>('/api/setup')
      .then((res) => {
        setNeedsSetup(res.needsSetup);
        if (res.needsSetup) setViewMode('setup');
      })
      .catch(() => {});

    getJSON<{ enabled: boolean; issuerUrl: string }>('/api/auth/sso-config')
      .then((res) => setSSOConfig(res))
      .catch(() => {});
  }, []);

  const handleLoginSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');

    try {
      // 1. Fetch user's KDF params
      const params = await getJSON<{ salt: string; iterations: number }>(
        `/api/auth/login-params?username=${encodeURIComponent(username)}`
      );

      // 2. Derive authSecret client-side
      const authSecret = await deriveAuthSecret(password, params.salt, params.iterations);

      // 3. Authenticate with backend
      const res = await postJSON<{ ok: boolean; user: any }>('/api/auth/login', {
        username,
        password,
        authSecret,
      });

      // 4. Derive wrapping key and unwrap user's vault key
      const passKey = await deriveKeyFromPassword(password, params.salt, params.iterations);
      let vaultKey: CryptoKey;

      if (res.user.passwordKeyWrap) {
        vaultKey = await unwrapVaultKey(res.user.passwordKeyWrap, passKey);
      } else {
        // First login or missing wrap: create new vault key and wrap it
        vaultKey = await generateVaultKey();
        const wrapped = await wrapVaultKey(vaultKey, passKey);
        await postJSON('/api/auth/key-wraps', { passwordKeyWrap: wrapped });
      }

      onLoginSuccess(res.user, vaultKey);
    } catch (err) {
      setError(toErrorMessage(err, 'Invalid username or password'));
    } finally {
      setBusy(false);
    }
  };

  const handleSetupSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');

    try {
      const salt = generateRandomHex(16);
      const iterations = 600000;
      const authSecret = await deriveAuthSecret(password, salt, iterations);

      // Generate 256-bit vault master key
      const vaultKey = await generateVaultKey();

      // Wrap under master password
      const passKey = await deriveKeyFromPassword(password, salt, iterations);
      const passwordKeyWrap = await wrapVaultKey(vaultKey, passKey);

      // Wrap under paper recovery key
      const paperKey = generatePaperRecoveryKey();
      const cleanPaper = paperKey.replace(/-/g, '');
      const paperWrappingKey = await deriveKeyFromPassword(cleanPaper, salt, iterations);
      const recoveryKeyWrap = await wrapVaultKey(vaultKey, paperWrappingKey);
      const recoveryVerifier = await deriveAuthSecret(cleanPaper, salt, iterations);

      const res = await postJSON<{ ok: boolean; user: any }>('/api/setup', {
        username,
        email,
        displayName: displayName || username,
        password,
        authSecret,
        authSalt: salt,
        kdfIterations: iterations,
        passwordKeyWrap,
        recoveryKeyWrap,
        recoveryVerifier,
      });

      setGeneratedPaperKey(paperKey);
      // Wait for user to record paper key before entering app
      onLoginSuccess(res.user, vaultKey);
    } catch (err) {
      setError(toErrorMessage(err, 'Failed to initialize administrator account'));
    } finally {
      setBusy(false);
    }
  };

  const handleRecoverySubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');

    try {
      const res = await postJSON<{ ok: boolean; user: any }>('/api/auth/recovery', {
        username,
        recoverySecret,
      });

      const cleanPaper = recoverySecret.replace(/-/g, '').toUpperCase();
      const paperWrappingKey = await deriveKeyFromPassword(cleanPaper, res.user.authSalt, res.user.kdfIterations || 600000);
      const vaultKey = await unwrapVaultKey(res.user.recoveryKeyWrap, paperWrappingKey);

      onLoginSuccess(res.user, vaultKey);
    } catch (err) {
      setError(toErrorMessage(err, 'Invalid recovery key or username'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem', backgroundColor: 'var(--bg-primary)' }}>
      <div className="modal-card" style={{ maxWidth: '440px', width: '100%' }}>
        <div style={{ padding: '2rem 1.75rem 1rem', textAlign: 'center' }}>
          <div style={{ display: 'inline-flex', padding: '0.75rem', borderRadius: '12px', background: 'var(--cyan-dim)', color: 'var(--cyan)', marginBottom: '0.75rem' }}>
            <Bookmark size={32} />
          </div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)' }}>KyBookmarks</h1>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            {viewMode === 'setup'
              ? 'First-Time Administrator Setup'
              : viewMode === 'recovery'
              ? 'Vault Emergency Recovery'
              : 'Zero-Knowledge Encrypted Bookmark Manager'}
          </p>
        </div>

        <div style={{ padding: '1.25rem 1.75rem 2rem' }}>
          {error && (
            <div className="alert alert-error">
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          {viewMode === 'login' && (
            <>
              {ssoConfig?.enabled && (
                <div style={{ marginBottom: '1.25rem' }}>
                  <a
                    href="/api/auth/oidc/login"
                    className="btn btn-secondary"
                    style={{ width: '100%', borderColor: 'rgba(77, 238, 234, 0.4)', color: 'var(--cyan)', display: 'flex', justifyContent: 'center' }}
                  >
                    <ShieldCheck size={18} />
                    <span>Sign In with KySignOn SSO</span>
                  </a>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: '1.25rem 0', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    <div style={{ flex: 1, height: '1px', background: 'var(--border-color)' }} />
                    <span>Or Master Password</span>
                    <div style={{ flex: 1, height: '1px', background: 'var(--border-color)' }} />
                  </div>
                </div>
              )}

              <form onSubmit={handleLoginSubmit}>
                <div className="form-group">
                  <label className="form-label">Username or Email</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="e.g. alice"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    autoFocus
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Master Password</label>
                  <input
                    type="password"
                    className="input"
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>

                <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '0.5rem' }} disabled={busy}>
                  {busy ? <RefreshCw size={16} className="spin" /> : <Lock size={16} />}
                  <span>Unlock Vault</span>
                </button>
              </form>

              <div style={{ marginTop: '1.25rem', textAlign: 'center' }}>
                <button
                  type="button"
                  onClick={() => setViewMode('recovery')}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '0.8rem', cursor: 'pointer' }}
                >
                  Lost password? Use paper recovery key
                </button>
              </div>
            </>
          )}

          {viewMode === 'setup' && (
            <form onSubmit={handleSetupSubmit}>
              <div className="form-group">
                <label className="form-label">Admin Username</label>
                <input
                  type="text"
                  className="input"
                  placeholder="admin"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Admin Email</label>
                <input
                  type="email"
                  className="input"
                  placeholder="admin@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Display Name</label>
                <input
                  type="text"
                  className="input"
                  placeholder="Administrator"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Master Password (min 12 chars)</label>
                <input
                  type="password"
                  className="input"
                  placeholder="••••••••••••"
                  minLength={12}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '0.5rem' }} disabled={busy}>
                {busy ? <RefreshCw size={16} className="spin" /> : <ShieldCheck size={16} />}
                <span>Initialize Vault & Server</span>
              </button>
            </form>
          )}

          {viewMode === 'recovery' && (
            <form onSubmit={handleRecoverySubmit}>
              <div className="form-group">
                <label className="form-label">Username or Email</label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. alice"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">24-Character Paper Recovery Key</label>
                <input
                  type="text"
                  className="input input-mono"
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  value={recoverySecret}
                  onChange={(e) => setRecoverySecret(e.target.value)}
                  required
                />
              </div>

              <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '0.5rem' }} disabled={busy}>
                {busy ? <RefreshCw size={16} className="spin" /> : <Key size={16} />}
                <span>Unlock with Recovery Key</span>
              </button>

              <div style={{ marginTop: '1.25rem', textAlign: 'center' }}>
                <button
                  type="button"
                  onClick={() => setViewMode('login')}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '0.8rem', cursor: 'pointer' }}
                >
                  Back to Password Sign In
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
