import React from 'react';
import { AlertTriangle, Check, RefreshCw, X } from 'lucide-react';

interface ReconciliationModalProps {
  conflicts: any[];
  onClose: () => void;
  onResolved: () => void;
}

export const ReconciliationModal: React.FC<ReconciliationModalProps> = ({
  conflicts,
  onClose,
  onResolved,
}) => {
  return (
    <div className="modal-overlay">
      <div className="modal-card" style={{ maxWidth: '640px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle color="var(--accent-amber)" size={20} />
            <h3 className="modal-title">Sync Conflict Reconciliation</h3>
          </div>
          <button className="icon-btn" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
            Concurrent updates occurred from multiple devices. In accordance with zero-knowledge protocol,
            failed writes are preserved for 90 days rather than discarded.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {conflicts.map((c, i) => (
              <div
                key={i}
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius)',
                  padding: '1rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                    Object ID: <code className="font-mono">{c.objectId}</code>
                  </span>
                  <span className="brand-badge">Version {c.version}</span>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
                  <button className="btn btn-primary btn-sm" onClick={onResolved}>
                    <Check size={14} />
                    <span>Keep Local Version</span>
                  </button>
                  <button className="btn btn-secondary btn-sm" onClick={onResolved}>
                    <RefreshCw size={14} />
                    <span>Accept Server Version</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-primary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
