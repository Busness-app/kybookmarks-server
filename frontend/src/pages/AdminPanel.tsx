import React, { useState, useEffect } from 'react';
import { getJSON, postJSON, putJSON, deleteJSON, toErrorMessage } from '../lib/api';
import { AdminBackup } from './AdminBackup';
import {
  Users,
  ShieldCheck,
  FileText,
  HardDriveDownload,
  Plus,
  Trash2,
  Edit2,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Check,
} from 'lucide-react';

interface AdminPanelProps {
  currentUser: any;
}

export const AdminPanel: React.FC<AdminPanelProps> = ({ currentUser }) => {
  const [activeTab, setActiveTab] = useState<'users' | 'sso' | 'audit' | 'backup'>('users');

  // Users
  const [users, setUsers] = useState<any[]>([]);
  const [showUserModal, setShowUserModal] = useState(false);
  const [editingUser, setEditingUser] = useState<any | null>(null);
  const [formUsername, setFormUsername] = useState('');
  const [formEmail, setFormEmail] = useState('');
  const [formDisplayName, setFormDisplayName] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formRole, setFormRole] = useState('user');
  const [formStatus, setFormStatus] = useState('active');

  // SSO
  const [ssoSettings, setSSOSettings] = useState<{
    enabled: boolean;
    issuerUrl: string;
    clientId: string;
    clientSecret?: string;
    redirectUri?: string;
    autoProvision: boolean;
  }>({
    enabled: false,
    issuerUrl: 'https://auth.urlxl.com',
    clientId: 'kybookmarks',
    redirectUri: '',
    autoProvision: true,
  });

  // Audit
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [auditStatus, setAuditStatus] = useState<{ valid?: boolean; count?: number; error?: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (activeTab === 'users') fetchUsers();
    if (activeTab === 'sso') fetchSSO();
    if (activeTab === 'audit') fetchAudit();
  }, [activeTab]);

  const fetchUsers = () => {
    getJSON<{ users: any[] }>('/api/admin/users')
      .then((res) => setUsers(res.users || []))
      .catch(() => {});
  };

  const fetchSSO = () => {
    getJSON<any>('/api/admin/sso')
      .then((res) => {
        if (res) setSSOSettings(res);
      })
      .catch(() => {});
  };

  const fetchAudit = () => {
    getJSON<{ entries: any[] }>('/api/admin/audit?limit=100')
      .then((res) => setAuditLogs(res.entries || []))
      .catch(() => {});
  };

  const handleSaveUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (editingUser) {
        await putJSON(`/api/admin/users/${editingUser.id}`, {
          displayName: formDisplayName,
          email: formEmail,
          role: formRole,
          status: formStatus,
          password: formPassword || undefined,
        });
      } else {
        await postJSON('/api/admin/users', {
          username: formUsername,
          email: formEmail,
          displayName: formDisplayName || formUsername,
          password: formPassword,
          role: formRole,
          status: formStatus,
        });
      }
      setShowUserModal(false);
      setEditingUser(null);
      setFormUsername('');
      setFormEmail('');
      setFormDisplayName('');
      setFormPassword('');
      fetchUsers();
    } catch (err) {
      alert(toErrorMessage(err, 'Failed to save user'));
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteUser = async (id: string) => {
    if (!confirm('Are you sure you want to delete this user?')) return;
    try {
      await deleteJSON(`/api/admin/users/${id}`);
      fetchUsers();
    } catch (err) {
      alert(toErrorMessage(err, 'Failed to delete user'));
    }
  };

  const handleSaveSSO = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await postJSON('/api/admin/sso', ssoSettings);
      alert('SSO settings saved successfully!');
    } catch (err) {
      alert(toErrorMessage(err, 'Failed to save SSO settings'));
    } finally {
      setBusy(false);
    }
  };

  const handleVerifyAuditChain = async () => {
    setBusy(true);
    try {
      const res = await postJSON<{ valid: boolean; count: number; error: string }>('/api/admin/audit/verify');
      setAuditStatus(res);
    } catch (err) {
      alert(toErrorMessage(err, 'Failed to verify audit logs'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="view-container" style={{ overflowY: 'auto', padding: '2rem' }}>
      <div style={{ maxWidth: '960px', margin: '0 auto', width: '100%' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.25rem' }}>
          KyBookmarks Administration
        </h1>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.75rem' }}>
          Manage user accounts, KySignOn SSO discovery, and tamper-evident cryptographic audit logs.
        </p>

        {/* Tab Navigation */}
        <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border-color)', marginBottom: '1.5rem' }}>
          <button
            className={`nav-item ${activeTab === 'users' ? 'active' : ''}`}
            onClick={() => setActiveTab('users')}
          >
            <Users size={16} />
            <span>User Accounts</span>
          </button>
          <button
            className={`nav-item ${activeTab === 'sso' ? 'active' : ''}`}
            onClick={() => setActiveTab('sso')}
          >
            <ShieldCheck size={16} />
            <span>Single Sign-On (OIDC)</span>
          </button>
          <button
            className={`nav-item ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            <FileText size={16} />
            <span>Audit Trail</span>
          </button>
          <button
            className={`nav-item ${activeTab === 'backup' ? 'active' : ''}`}
            onClick={() => setActiveTab('backup')}
          >
            <HardDriveDownload size={16} />
            <span>Backup &amp; Recovery</span>
          </button>
        </div>

        {/* Backup Tab */}
        {activeTab === 'backup' && <AdminBackup />}

        {/* Users Tab */}
        {activeTab === 'users' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                Total Accounts: <strong>{users.length}</strong>
              </div>
              <button
                className="btn btn-primary btn-sm"
                onClick={() => {
                  setEditingUser(null);
                  setFormUsername('');
                  setFormEmail('');
                  setFormDisplayName('');
                  setFormPassword('');
                  setFormRole('user');
                  setFormStatus('active');
                  setShowUserModal(true);
                }}
              >
                <Plus size={14} />
                <span>Create User</span>
              </button>
            </div>

            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Display Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>SSO Linked</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td className="font-mono" style={{ fontWeight: 600, color: 'var(--cyan)' }}>
                        {u.username}
                      </td>
                      <td>{u.displayName}</td>
                      <td style={{ color: 'var(--text-secondary)' }}>{u.email}</td>
                      <td>
                        <span className="brand-badge">{u.role.toUpperCase()}</span>
                      </td>
                      <td>
                        <span
                          style={{
                            color: u.status === 'active' ? 'var(--accent-green)' : 'var(--accent-red)',
                            fontWeight: 600,
                          }}
                        >
                          {u.status}
                        </span>
                      </td>
                      <td>{u.ssoSubject ? <Check size={16} color="var(--accent-green)" /> : '—'}</td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '0.25rem' }}>
                          <button
                            className="icon-btn"
                            onClick={() => {
                              setEditingUser(u);
                              setFormUsername(u.username);
                              setFormEmail(u.email);
                              setFormDisplayName(u.displayName);
                              setFormPassword('');
                              setFormRole(u.role);
                              setFormStatus(u.status);
                              setShowUserModal(true);
                            }}
                            title="Edit"
                          >
                            <Edit2 size={14} />
                          </button>
                          {u.id !== currentUser.id && (
                            <button
                              className="icon-btn danger"
                              onClick={() => handleDeleteUser(u.id)}
                              title="Delete"
                            >
                              <Trash2 size={14} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* SSO Settings Tab */}
        {activeTab === 'sso' && (
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '1.5rem' }}>
            <form onSubmit={handleSaveSSO}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
                <input
                  type="checkbox"
                  id="ssoEnabled"
                  checked={ssoSettings.enabled}
                  onChange={(e) => setSSOSettings({ ...ssoSettings, enabled: e.target.checked })}
                  style={{ width: '18px', height: '18px', accentColor: 'var(--cyan)' }}
                />
                <label htmlFor="ssoEnabled" style={{ fontWeight: 600, fontSize: '1rem', cursor: 'pointer' }}>
                  Enable OpenID Connect / KySignOn Single Sign-On
                </label>
              </div>

              <div className="form-group">
                <label className="form-label">OIDC Issuer URL</label>
                <input
                  type="text"
                  className="input input-mono"
                  placeholder="https://auth.urlxl.com or http://localhost:5867"
                  value={ssoSettings.issuerUrl}
                  onChange={(e) => setSSOSettings({ ...ssoSettings, issuerUrl: e.target.value })}
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">Client ID</label>
                  <input
                    type="text"
                    className="input input-mono"
                    placeholder="kybookmarks"
                    value={ssoSettings.clientId}
                    onChange={(e) => setSSOSettings({ ...ssoSettings, clientId: e.target.value })}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Client Secret (optional for PKCE)</label>
                  <input
                    type="password"
                    className="input input-mono"
                    placeholder="••••••••"
                    value={ssoSettings.clientSecret || ''}
                    onChange={(e) => setSSOSettings({ ...ssoSettings, clientSecret: e.target.value })}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Custom Redirect URI (optional override)</label>
                <input
                  type="text"
                  className="input input-mono"
                  placeholder="https://bookmarks.urlxl.com/api/auth/oidc/callback"
                  value={ssoSettings.redirectUri || ''}
                  onChange={(e) => setSSOSettings({ ...ssoSettings, redirectUri: e.target.value })}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', margin: '1.25rem 0' }}>
                <input
                  type="checkbox"
                  id="autoProv"
                  checked={ssoSettings.autoProvision}
                  onChange={(e) => setSSOSettings({ ...ssoSettings, autoProvision: e.target.checked })}
                  style={{ width: '16px', height: '16px', accentColor: 'var(--cyan)' }}
                />
                <label htmlFor="autoProv" style={{ fontSize: '0.9rem', cursor: 'pointer' }}>
                  Auto-provision new accounts on first SSO login
                </label>
              </div>

              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy ? <RefreshCw size={14} className="spin" /> : <ShieldCheck size={14} />}
                <span>Save SSO Settings</span>
              </button>
            </form>
          </div>
        )}

        {/* Audit Tab */}
        {activeTab === 'audit' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div>
                <button className="btn btn-secondary btn-sm" onClick={handleVerifyAuditChain} disabled={busy}>
                  <CheckCircle size={14} color="var(--cyan)" />
                  <span>Verify SHA-256 Hash Chain</span>
                </button>
              </div>

              {auditStatus && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    fontSize: '0.85rem',
                    color: auditStatus.valid ? 'var(--accent-green)' : 'var(--accent-red)',
                  }}
                >
                  {auditStatus.valid ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
                  <span>
                    {auditStatus.valid
                      ? `Cryptographic chain valid (${auditStatus.count} entries)`
                      : `Hash chain verification failed: ${auditStatus.error}`}
                  </span>
                </div>
              )}
            </div>

            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Actor / User</th>
                    <th>IP</th>
                    <th>Details</th>
                    <th>Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((entry) => (
                    <tr key={entry.id}>
                      <td className="font-mono text-muted" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                        {new Date(entry.timestamp).toLocaleString()}
                      </td>
                      <td style={{ fontWeight: 600, color: 'var(--cyan)' }}>{entry.action}</td>
                      <td className="font-mono" style={{ fontSize: '0.8rem' }}>
                        {entry.userId || 'system'}
                      </td>
                      <td className="font-mono text-muted" style={{ fontSize: '0.8rem' }}>
                        {entry.ip}
                      </td>
                      <td style={{ fontSize: '0.85rem' }}>{entry.details}</td>
                      <td className="font-mono text-muted" style={{ fontSize: '0.7rem' }} title={entry.hash}>
                        {entry.hash.slice(0, 10)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* User Create/Edit Modal */}
        {showUserModal && (
          <div className="modal-overlay">
            <div className="modal-card">
              <div className="modal-header">
                <h3 className="modal-title">{editingUser ? 'Edit User' : 'Create User'}</h3>
                <button className="icon-btn" onClick={() => setShowUserModal(false)}>
                  ✕
                </button>
              </div>
              <form onSubmit={handleSaveUser}>
                <div className="modal-body">
                  {!editingUser && (
                    <div className="form-group">
                      <label className="form-label">Username</label>
                      <input
                        type="text"
                        className="input"
                        placeholder="e.g. bob"
                        value={formUsername}
                        onChange={(e) => setFormUsername(e.target.value)}
                        required
                        autoFocus
                      />
                    </div>
                  )}

                  <div className="form-group">
                    <label className="form-label">Email</label>
                    <input
                      type="email"
                      className="input"
                      placeholder="bob@example.com"
                      value={formEmail}
                      onChange={(e) => setFormEmail(e.target.value)}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">Display Name</label>
                    <input
                      type="text"
                      className="input"
                      placeholder="Bob Builder"
                      value={formDisplayName}
                      onChange={(e) => setFormDisplayName(e.target.value)}
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">
                      {editingUser ? 'Reset Password (optional)' : 'Initial Password (min 12 chars)'}
                    </label>
                    <input
                      type="password"
                      className="input"
                      placeholder="••••••••••••"
                      minLength={editingUser ? 0 : 12}
                      value={formPassword}
                      onChange={(e) => setFormPassword(e.target.value)}
                      required={!editingUser}
                    />
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <div className="form-group">
                      <label className="form-label">Role</label>
                      <select className="input" value={formRole} onChange={(e) => setFormRole(e.target.value)}>
                        <option value="user">User</option>
                        <option value="admin">Administrator</option>
                      </select>
                    </div>

                    <div className="form-group">
                      <label className="form-label">Status</label>
                      <select className="input" value={formStatus} onChange={(e) => setFormStatus(e.target.value)}>
                        <option value="active">Active</option>
                        <option value="suspended">Suspended</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="modal-footer">
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setShowUserModal(false)}
                  >
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={busy}>
                    <span>Save User</span>
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
