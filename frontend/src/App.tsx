import React, { useState, useEffect } from 'react';
import { getJSON, postJSON } from './lib/api';
import { LoginPage } from './pages/LoginPage';
import { BookmarksPage } from './pages/BookmarksPage';
import { SecuritySettings } from './pages/SecuritySettings';
import { AdminPanel } from './pages/AdminPanel';
import { DevicePairingModal } from './pages/DevicePairingModal';
import { ReconciliationModal } from './pages/ReconciliationModal';
import {
  Bookmark,
  ShieldCheck,
  Smartphone,
  LogOut,
  Settings,
  Shield,
  Layers,
  Key,
} from 'lucide-react';

export const App: React.FC = () => {
  const [user, setUser] = useState<any | null>(null);
  const [vaultKey, setVaultKey] = useState<CryptoKey | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'bookmarks' | 'security' | 'admin'>('bookmarks');

  // Modals
  const [showPairingModal, setShowPairingModal] = useState(false);
  const [reconciliationConflicts, setReconciliationConflicts] = useState<any[] | null>(null);

  useEffect(() => {
    getJSON('/api/auth/me')
      .then((u) => {
        setUser(u);
      })
      .catch(() => {
        setUser(null);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const handleLoginSuccess = (loggedInUser: any, key: CryptoKey) => {
    setUser(loggedInUser);
    setVaultKey(key);
  };

  const handleLogout = async () => {
    try {
      await postJSON('/api/auth/logout');
    } catch {}
    setUser(null);
    setVaultKey(null);
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: 'var(--bg-primary)', color: 'var(--cyan)' }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1rem', letterSpacing: '0.1em' }}>
          LOADING KYBOOKMARKS...
        </div>
      </div>
    );
  }

  if (!user || !vaultKey) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="app-container">
      {/* Navbar */}
      <nav className="navbar">
        <div className="nav-brand">
          <Bookmark size={22} />
          <span>KyBookmarks</span>
          <span className="brand-badge">E2EE ZERO-KNOWLEDGE</span>
        </div>

        <div className="nav-center">
          <button
            className={`nav-item ${activeTab === 'bookmarks' ? 'active' : ''}`}
            onClick={() => setActiveTab('bookmarks')}
          >
            <Bookmark size={16} />
            <span>Bookmarks</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'security' ? 'active' : ''}`}
            onClick={() => setActiveTab('security')}
          >
            <Key size={16} />
            <span>Vault Security</span>
          </button>

          {user.role === 'admin' && (
            <button
              className={`nav-item ${activeTab === 'admin' ? 'active' : ''}`}
              onClick={() => setActiveTab('admin')}
            >
              <ShieldCheck size={16} />
              <span>Admin Panel</span>
            </button>
          )}
        </div>

        <div className="nav-right">
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => setShowPairingModal(true)}
            title="Pair Mobile App or Browser Extension"
          >
            <Smartphone size={14} />
            <span>Pair Device</span>
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'var(--bg-card)', padding: '0.35rem 0.75rem', borderRadius: 'var(--radius)', border: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
            <span style={{ fontWeight: 600 }}>{user.displayName || user.username}</span>
            <span className="brand-badge">{user.role.toUpperCase()}</span>
          </div>

          <button className="icon-btn" onClick={handleLogout} title="Sign Out">
            <LogOut size={16} />
          </button>
        </div>
      </nav>

      {/* Main View Area */}
      {activeTab === 'bookmarks' && (
        <BookmarksPage
          user={user}
          vaultKey={vaultKey}
          onOpenPairing={() => setShowPairingModal(true)}
          onOpenReconciliation={(conflicts) => setReconciliationConflicts(conflicts)}
        />
      )}

      {activeTab === 'security' && (
        <SecuritySettings
          user={user}
          vaultKey={vaultKey}
          onUserUpdated={(u) => setUser(u)}
        />
      )}

      {activeTab === 'admin' && <AdminPanel currentUser={user} />}

      {/* Device Pairing Modal */}
      {showPairingModal && (
        <DevicePairingModal
          user={user}
          vaultKey={vaultKey}
          onClose={() => setShowPairingModal(false)}
        />
      )}

      {/* Reconciliation Modal */}
      {reconciliationConflicts && (
        <ReconciliationModal
          conflicts={reconciliationConflicts}
          onClose={() => setReconciliationConflicts(null)}
          onResolved={() => setReconciliationConflicts(null)}
        />
      )}
    </div>
  );
};
