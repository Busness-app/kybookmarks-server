import React, { useState, useEffect } from 'react';
import { getJSON, postJSON, deleteJSON, toErrorMessage } from '../lib/api';
import {
  generateRandomHex,
  deriveKeyFromPassword,
  wrapVaultKey,
  generatePaperRecoveryKey,
  deriveAuthSecret,
} from '../lib/crypto';
import {
  Key,
  ShieldCheck,
  Smartphone,
  Trash2,
  Check,
  Copy,
  RefreshCw,
  AlertCircle,
  Lock,
} from 'lucide-react';

interface SecuritySettingsProps {
  user: any;
  vaultKey: CryptoKey;
  onUserUpdated: (u: any) => void;
}

export const SecuritySettings: React.FC<SecuritySettingsProps> = ({
  user,
  vaultKey,
  onUserUpdated,
}) => {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [generatedPaperKey, setGeneratedPaperKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  const [devices, setDevices] = useState<any[]>([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; type: 'error' | 'success' } | null>(null);

  useEffect(() => {
    fetchDevices();
  }, []);

  const fetchDevices = () => {
    getJSON<{ devices: any[] }>('/api/devices')
      .then((res) => setDevices(res.devices || []))
      .catch(() => {});
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setMsg({ text: 'New passwords do not match', type: 'error' });
      return;
    }
    setBusy(true);
    setMsg(null);

    try {
      const salt = generateRandomHex(16);
      const iterations = 600000;
      const authSecret = await deriveAuthSecret(newPassword, salt, iterations);

      // Re-wrap the existing vault key under the new password
      const newWrappingKey = await deriveKeyFromPassword(newPassword, salt, iterations);
      const newPasswordKeyWrap = await wrapVaultKey(vaultKey, newWrappingKey);

      await postJSON('/api/auth/password', {
        oldPassword,
        newPassword,
        newAuthSecret: authSecret,
        newAuthSalt: salt,
        passwordKeyWrap: newPasswordKeyWrap,
      });

      setMsg({ text: 'Master password updated and vault re-wrapped successfully!', type: 'success' });
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setMsg({ text: toErrorMessage(err, 'Failed to update master password'), type: 'error' });
    } finally {
      setBusy(false);
    }
  };

  const handleGenerateRecoveryKey = async () => {
    setBusy(true);
    setMsg(null);

    try {
      const paperKey = generatePaperRecoveryKey();
      const cleanPaper = paperKey.replace(/-/g, '');
      const salt = user.authSalt || generateRandomHex(16);
      const iterations = user.kdfIterations || 600000;

      const paperWrappingKey = await deriveKeyFromPassword(cleanPaper, salt, iterations);
      const recoveryKeyWrap = await wrapVaultKey(vaultKey, paperWrappingKey);
      const recoveryVerifier = await deriveAuthSecret(cleanPaper, salt, iterations);

      await postJSON('/api/auth/key-wraps', {
        recoveryKeyWrap,
        recoveryVerifier,
      });

      setGeneratedPaperKey(paperKey);
      setMsg({ text: 'New emergency recovery key generated and sealed!', type: 'success' });
    } catch (err) {
      setMsg({ text: toErrorMessage(err, 'Failed to generate recovery key'), type: 'error' });
    } finally {
      setBusy(false);
    }
  };

  const handleRevokeDevice = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this trusted device?')) return;
    try {
      await deleteJSON(`/api/devices/${id}`);
      fetchDevices();
    } catch (err) {
      alert(toErrorMessage(err, 'Failed to revoke device'));
    }
  };

  const handleSSOUnlink = async () => {
    if (!confirm('Are you sure you want to unlink your KySignOn account?')) return;
    try {
      await postJSON('/api/settings/sso/unlink');
      onUserUpdated({ ...user, ssoSubject: '' });
      alert('SSO account unlinked');
    } catch (err) {
      alert(toErrorMessage(err, 'Failed to unlink SSO'));
    }
  };

  return (
    <div className="view-container" style={{ overflowY: 'auto', padding: '2rem' }}>
      <div style={{ maxWidth: '720px', margin: '0 auto', width: '100%' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.25rem' }}>
          Security & Vault Encryption
        </h1>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.75rem' }}>
          Manage your zero-knowledge master key, paper recovery backup, and trusted browser extensions.
        </p>

        {msg && (
          <div className={`alert ${msg.type === 'error' ? 'alert-error' : 'alert-success'}`}>
            {msg.type === 'error' ? <AlertCircle size={16} /> : <Check size={16} />}
            <span>{msg.text}</span>
          </div>
        )}

        {/* Change Password */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '1.5rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <Lock size={18} color="var(--cyan)" />
            <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Change Master Password</h2>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Changing your password will re-wrap your 256-bit vault key envelope. Existing encrypted bookmarks do not need to be re-encrypted.
          </p>

          <form onSubmit={handleChangePassword}>
            <div className="form-group">
              <label className="form-label">Current Password</label>
              <input
                type="password"
                className="input"
                placeholder="••••••••••••"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                required
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label className="form-label">New Password (min 12 chars)</label>
                <input
                  type="password"
                  className="input"
                  placeholder="••••••••••••"
                  minLength={12}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Confirm New Password</label>
                <input
                  type="password"
                  className="input"
                  placeholder="••••••••••••"
                  minLength={12}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                />
              </div>
            </div>

            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? <RefreshCw size={14} className="spin" /> : <ShieldCheck size={14} />}
              <span>Update Password & Re-Wrap Vault</span>
            </button>
          </form>
        </div>

        {/* Paper Recovery Key */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '1.5rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <Key size={18} color="var(--cyan)" />
            <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Emergency Paper Recovery Key</h2>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            A 24-character backup key capable of unlocking your encrypted vault if your master password is lost.
          </p>

          {generatedPaperKey && (
            <div style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: 'var(--radius)', border: '1px solid var(--cyan)', marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--cyan)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                Your Emergency Recovery Key (Save in a safe location)
              </div>
              <div style={{ fontSize: '1.25rem', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.08em', color: '#fff', margin: '0.5rem 0' }}>
                {generatedPaperKey}
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  navigator.clipboard.writeText(generatedPaperKey);
                  setCopiedKey(true);
                  setTimeout(() => setCopiedKey(false), 2000);
                }}
              >
                {copiedKey ? <Check size={14} color="var(--accent-green)" /> : <Copy size={14} />}
                <span>{copiedKey ? 'Copied to Clipboard' : 'Copy Key'}</span>
              </button>
            </div>
          )}

          <button className="btn btn-secondary" onClick={handleGenerateRecoveryKey} disabled={busy}>
            <Key size={14} />
            <span>{user.recoveryKeyWrap ? 'Generate New Recovery Key' : 'Create Paper Recovery Key'}</span>
          </button>
        </div>

        {/* SSO Connection */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '1.5rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <ShieldCheck size={18} color="var(--cyan)" />
            <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>KySignOn Single Sign-On</h2>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            {user.ssoSubject
              ? 'Your account is linked to KySignOn SSO. You can sign in using organizational credentials.'
              : 'Link this account to KySignOn SSO for one-click authentication.'}
          </p>

          {user.ssoSubject ? (
            <button className="btn btn-danger btn-sm" onClick={handleSSOUnlink}>
              <span>Unlink KySignOn SSO</span>
            </button>
          ) : (
            <a href="/api/auth/oidc/login?link=true" className="btn btn-secondary btn-sm">
              <ShieldCheck size={14} />
              <span>Link KySignOn SSO</span>
            </a>
          )}
        </div>

        {/* Paired Devices */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <Smartphone size={18} color="var(--cyan)" />
            <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Trusted Devices & Extensions</h2>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Devices authorized with an encrypted vault key envelope.
          </p>

          {devices.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              No other paired devices registered.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {devices.map((d) => (
                <div
                  key={d.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0.75rem 1rem',
                    background: 'var(--bg-secondary)',
                    borderRadius: 'var(--radius)',
                    border: '1px solid var(--border-color)',
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{d.deviceName}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Type: <code className="font-mono">{d.deviceType}</code> | Last seen:{' '}
                      {new Date(d.lastSeenAt).toLocaleDateString()}
                    </div>
                  </div>

                  <button
                    className="icon-btn danger"
                    onClick={() => handleRevokeDevice(d.id)}
                    title="Revoke Device"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
