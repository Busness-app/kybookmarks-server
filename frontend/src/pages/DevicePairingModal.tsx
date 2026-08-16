import React, { useState, useEffect, useRef } from 'react';
import QRCode from 'qrcode';
import { postJSON, toErrorMessage } from '../lib/api';
import { wrapVaultKey } from '../lib/crypto';
import { Smartphone, Clock, Check, RefreshCw, AlertCircle } from 'lucide-react';

interface DevicePairingModalProps {
  user: any;
  vaultKey: CryptoKey;
  onClose: () => void;
}

export const DevicePairingModal: React.FC<DevicePairingModalProps> = ({
  user,
  vaultKey,
  onClose,
}) => {
  const [pin, setPin] = useState('');
  const [token, setToken] = useState('');
  const [expiresIn, setExpiresIn] = useState(90);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Generate pairing session
  const generateSession = async () => {
    setBusy(true);
    setError('');
    try {
      const sess = await postJSON<{ pin: string; pairingToken: string }>('/api/devices/pair/request', {
        userId: user.id,
        deviceName: 'KyBookmarks Browser Extension / App',
        deviceType: 'browser_chrome',
      });

      setPin(sess.pin);
      setToken(sess.pairingToken);
      setExpiresIn(90);

      // Render QR
      if (canvasRef.current) {
        const qrData = JSON.stringify({
          pin: sess.pin,
          token: sess.pairingToken,
          issuer: window.location.origin,
        });
        await QRCode.toCanvas(canvasRef.current, qrData, {
          width: 200,
          margin: 1,
          color: {
            dark: '#4deeea',
            light: '#0a0c10',
          },
        });
      }

      // Auto-approve this pairing with our active vaultKey
      // Wrap vaultKey with a temporary pairing secret derived from pin
      const tempKey = await window.crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(sess.pin.padEnd(32, '0')),
        { name: 'AES-GCM' },
        false,
        ['wrapKey']
      );
      const wrappedEnvelope = await wrapVaultKey(vaultKey, tempKey);

      await postJSON('/api/devices/pair/approve', {
        pin: sess.pin,
        vaultKeyEnvelope: wrappedEnvelope,
      });
    } catch (err) {
      setError(toErrorMessage(err, 'Failed to generate device pairing session'));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    generateSession();
  }, []);

  // 90s countdown ticker
  useEffect(() => {
    if (expiresIn <= 0) return;
    const timer = setInterval(() => {
      setExpiresIn((prev) => prev - 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [expiresIn]);

  return (
    <div className="modal-overlay">
      <div className="modal-card" style={{ maxWidth: '440px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Smartphone color="var(--cyan)" size={20} />
            <h3 className="modal-title">Pair Trusted Device</h3>
          </div>
          <button className="icon-btn" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body" style={{ textAlign: 'center' }}>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Open the KyBookmarks browser extension or mobile app and scan this QR code or enter the 6-digit PIN.
          </p>

          {error && (
            <div className="alert alert-error">
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1rem' }}>
            <canvas ref={canvasRef} style={{ borderRadius: '8px', border: '1px solid var(--border-color)' }} />
          </div>

          <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem', borderRadius: 'var(--radius)', border: '1px solid var(--border-color)', marginBottom: '1rem' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.25rem' }}>
              Pairing PIN
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--cyan)', letterSpacing: '0.2em' }}>
              {pin || '••••••'}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem', fontSize: '0.8rem', color: expiresIn > 0 ? 'var(--text-secondary)' : 'var(--accent-red)' }}>
            <Clock size={14} />
            <span>{expiresIn > 0 ? `Code expires in ${expiresIn}s` : 'Code expired'}</span>
          </div>
        </div>

        <div className="modal-footer" style={{ justifyContent: 'space-between' }}>
          <button className="btn btn-secondary btn-sm" onClick={generateSession} disabled={busy}>
            <RefreshCw size={14} className={busy ? 'spin' : ''} />
            <span>Generate New Code</span>
          </button>
          <button className="btn btn-primary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
