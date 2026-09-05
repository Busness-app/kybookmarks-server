import React, { useEffect, useState } from 'react';
import { getJSON, postJSON, putJSON, deleteJSON, toErrorMessage } from '../lib/api';
import {
  Play,
  Download,
  CheckCircle,
  XCircle,
  Loader2,
  Link2,
  Unlink,
  KeyRound,
  Send,
  AlertCircle,
  RefreshCw,
  Clock,
  HardDrive,
  Server,
} from 'lucide-react';
import './backup.css';

const HOUR = 3600;
const SCHEDULE_CHOICES: { label: string; sec: number }[] = [
  { label: 'Off', sec: 0 },
  { label: 'Every hour', sec: HOUR },
  { label: 'Every 6 hours', sec: 6 * HOUR },
  { label: 'Every 12 hours', sec: 12 * HOUR },
  { label: 'Daily', sec: 24 * HOUR },
  { label: 'Weekly', sec: 7 * 24 * HOUR },
];

interface LocalCopy {
  name: string;
  size_bytes: number;
  created_at: string;
}

interface Receipt {
  capsule_id: string;
  digest: string;
  size_bytes: number;
  deposited_at: string;
}

interface BackupStatus {
  paired: boolean;
  key_pinned: boolean;
  app_name: string;
  app_version: string;
  members: string[];
  allow_private_recovery: boolean;
  recovery_url?: string;
  recovery_key_id?: string;
  threshold?: number;
  total_shares?: number;
  recovery_key_error?: string;
  last_deposit?: Receipt;
  local_dir?: string;
  local_keep?: number;
  local_copies?: LocalCopy[];
  local_error?: string;
  interval_sec?: number;
  min_interval_sec?: number;
  next_run_at?: string;
}

interface DrillCheck {
  name: string;
  passed: boolean;
  message?: string;
}

interface DrillResult {
  passed: boolean;
  checks: DrillCheck[];
  error_message?: string;
  duration_ms: number;
  size_bytes?: number;
}

interface RunResult {
  manifest: { capsule_id: string };
  size_bytes: number;
  local_path?: string;
  local_error?: string;
  receipt?: Receipt;
}

function when(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function every(sec?: number): string {
  if (!sec) return 'Off';
  const hit = SCHEDULE_CHOICES.find((c) => c.sec === sec);
  if (hit) return hit.label;
  return sec % HOUR === 0 ? `Every ${sec / HOUR} hours` : `Every ${Math.round(sec / 60)} minutes`;
}

function bytes(n: number): string {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MiB`;
  if (n >= 1 << 10) return `${Math.round(n / (1 << 10))} KiB`;
  return `${n} B`;
}

const cardStyle: React.CSSProperties = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border-color)',
  borderRadius: '12px',
  padding: '1.5rem',
  marginBottom: '1.5rem',
};

const Badge: React.FC<{ tone: 'ok' | 'warn' | 'off'; children: React.ReactNode }> = ({ tone, children }) => (
  <span className={`dr-badge dr-badge-${tone}`}>{children}</span>
);

export const AdminBackup: React.FC = () => {
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [statusError, setStatusError] = useState('');

  const [running, setRunning] = useState(false);
  const [runMessage, setRunMessage] = useState('');
  const [runError, setRunError] = useState('');

  const [runningDrill, setRunningDrill] = useState(false);
  const [drillResult, setDrillResult] = useState<DrillResult | null>(null);

  const [scheduleSec, setScheduleSec] = useState(24 * HOUR);
  const [scheduleSaving, setScheduleSaving] = useState(false);
  const [scheduleMessage, setScheduleMessage] = useState('');
  const [scheduleError, setScheduleError] = useState('');

  const [remoteUrl, setRemoteUrl] = useState('');
  const [pairCode, setPairCode] = useState('');
  const [pairing, setPairing] = useState(false);
  const [pairMessage, setPairMessage] = useState('');
  const [pairError, setPairError] = useState('');
  const [unpairing, setUnpairing] = useState(false);

  const [pinKey, setPinKey] = useState('');
  const [pinK, setPinK] = useState('2');
  const [pinN, setPinN] = useState('3');
  const [pinning, setPinning] = useState(false);
  const [pinError, setPinError] = useState('');

  const fetchStatus = async () => {
    setLoadingStatus(true);
    setStatusError('');
    try {
      const data = await getJSON<BackupStatus>('/api/admin/backup/status');
      setStatus(data);
      if (data.recovery_url) setRemoteUrl(data.recovery_url);
      if (typeof data.interval_sec === 'number') setScheduleSec(data.interval_sec);
    } catch (err) {
      setStatusError(toErrorMessage(err, 'Could not load backup status'));
    } finally {
      setLoadingStatus(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const runBackup = async () => {
    setRunning(true);
    setRunMessage('');
    setRunError('');
    try {
      const res = await postJSON<RunResult>('/api/admin/backup/deposit');
      const went: string[] = [];
      if (res.local_path) went.push(`written to ${res.local_path}`);
      if (res.receipt) went.push(`deposited with KyRecovery at ${when(res.receipt.deposited_at)}`);
      setRunMessage(`Capsule ${res.manifest.capsule_id} (${bytes(res.size_bytes)}) ${went.join(' and ')}.`);
      if (res.local_error) setRunError(`The local copy failed: ${res.local_error}`);
    } catch (err) {
      setRunError(toErrorMessage(err, 'Backup failed'));
    } finally {
      setRunning(false);
      await fetchStatus();
    }
  };

  // A GET with cookies; withAdmin checks CSRF only on state-changing methods, and the
  // export is recorded on the audit chain before a byte is sent.
  const downloadCapsule = () => {
    window.location.assign('/api/admin/backup/export-capsule');
  };

  const runDrill = async () => {
    setRunningDrill(true);
    setDrillResult(null);
    try {
      setDrillResult(await postJSON<DrillResult>('/api/admin/backup/drill'));
    } catch (err) {
      const message = toErrorMessage(err, 'Restore drill failed to run');
      setDrillResult({ passed: false, duration_ms: 0, error_message: message, checks: [{ name: 'Execution', passed: false, message }] });
    } finally {
      setRunningDrill(false);
    }
  };

  const saveSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    setScheduleSaving(true);
    setScheduleMessage('');
    setScheduleError('');
    try {
      await putJSON('/api/admin/backup/schedule', { interval_sec: scheduleSec });
      setScheduleMessage(scheduleSec === 0 ? 'Automatic backups are off.' : `Backing up ${every(scheduleSec).toLowerCase()}.`);
      await fetchStatus();
    } catch (err) {
      setScheduleError(toErrorMessage(err, 'Could not save the schedule'));
    } finally {
      setScheduleSaving(false);
    }
  };

  const pair = async (e: React.FormEvent) => {
    e.preventDefault();
    setPairing(true);
    setPairMessage('');
    setPairError('');
    try {
      await postJSON('/api/admin/backup/pair-remote', { recovery_url: remoteUrl.trim(), pairing_code: pairCode.trim() });
      setPairMessage(`Paired with ${remoteUrl.trim()}.`);
      setPairCode('');
      await fetchStatus();
    } catch (err) {
      setPairError(toErrorMessage(err, 'Pairing failed'));
    } finally {
      setPairing(false);
    }
  };

  const unpair = async () => {
    if (
      !window.confirm(
        'Unpair from KyRecovery?\n\nRemoves the URL and sealed token rows. The key pin, receipts and local copies stay. The credential is dead only when the KyRecovery admin revokes it.'
      )
    )
      return;
    setUnpairing(true);
    setPairMessage('');
    setPairError('');
    try {
      await deleteJSON('/api/admin/backup/pairing');
      setPairMessage('Unpaired. Off-site backups have stopped; ask the KyRecovery admin to revoke this product there.');
      await fetchStatus();
    } catch (err) {
      setPairError(toErrorMessage(err, 'Could not unpair'));
    } finally {
      setUnpairing(false);
    }
  };

  const pin = async (e: React.FormEvent) => {
    e.preventDefault();
    setPinning(true);
    setPinError('');
    try {
      await postJSON('/api/admin/backup/pin-key', { public_key: pinKey.trim(), threshold: Number(pinK), total_shares: Number(pinN) });
      setPinKey('');
      await fetchStatus();
    } catch (err) {
      setPinError(toErrorMessage(err, 'Could not pin the key'));
    } finally {
      setPinning(false);
    }
  };

  const keyPinned = status?.key_pinned ?? false;
  const paired = status?.paired ?? false;
  const hasLocal = Boolean(status?.local_dir);
  const canBackUp = keyPinned && (paired || hasLocal);
  const scheduleOn = (status?.interval_sec ?? 0) > 0;
  const copies = status?.local_copies ?? [];
  const newestLocal = copies[0];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Backup &amp; Recovery</h2>
        <button type="button" className="btn btn-secondary btn-sm" onClick={fetchStatus} disabled={loadingStatus}>
          <RefreshCw size={14} className={loadingStatus ? 'dr-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {statusError && (
        <div className="alert alert-error">
          <AlertCircle size={16} /> <span>{statusError}</span>
        </div>
      )}
      {status?.recovery_key_error && (
        <div className="alert alert-error">
          <AlertCircle size={16} /> <span>{status.recovery_key_error}</span>
        </div>
      )}
      {status && !keyPinned && (
        <div className="alert alert-warning">
          <AlertCircle size={16} /> <span>No backups are being made. Pair with KyRecovery or pin the suite recovery key below.</span>
        </div>
      )}
      {status && keyPinned && !paired && !hasLocal && (
        <div className="alert alert-warning">
          <AlertCircle size={16} />{' '}
          <span>A key is pinned but capsules have nowhere to go. Pair with KyRecovery, or set KYBOOKMARKS_BACKUP_DIR to keep copies on this host.</span>
        </div>
      )}
      {status && keyPinned && !scheduleOn && (
        <div className="alert alert-warning">
          <Clock size={16} /> <span>Automatic backups are off. Only the button below makes one.</span>
        </div>
      )}

      <div className="dr-facts">
        <div className="dr-fact">
          <div className="dr-fact-label">
            <span>Recovery key</span>
            <Badge tone={keyPinned ? 'ok' : 'warn'}>{keyPinned ? 'Pinned' : 'None'}</Badge>
          </div>
          <div className="dr-fact-value dr-mono">{status?.recovery_key_id ?? '—'}</div>
          <div className="dr-fact-note">
            {keyPinned ? `${status?.threshold} of ${status?.total_shares} custodian cards open a capsule` : 'Nothing can be sealed until a key is pinned'}
          </div>
        </div>
        <div className="dr-fact">
          <div className="dr-fact-label">
            <span>KyRecovery</span>
            <Badge tone={paired ? 'ok' : 'off'}>{paired ? 'Paired' : 'Not paired'}</Badge>
          </div>
          <div className="dr-fact-value">{paired ? status?.recovery_url : 'No off-site copy'}</div>
          <div className="dr-fact-note">
            {status?.last_deposit ? `Last deposit ${when(status.last_deposit.deposited_at)}` : paired ? 'Nothing deposited yet' : ''}
          </div>
        </div>
        <div className="dr-fact">
          <div className="dr-fact-label">
            <span>Local copies</span>
            <Badge tone={hasLocal ? 'ok' : 'off'}>{hasLocal ? `${copies.length} of ${status?.local_keep}` : 'Off'}</Badge>
          </div>
          <div className="dr-fact-value dr-mono">{status?.local_dir ?? 'KYBOOKMARKS_BACKUP_DIR not set'}</div>
          <div className="dr-fact-note">{status?.local_error ?? (newestLocal ? `Newest ${when(newestLocal.created_at)}` : hasLocal ? 'Nothing written yet' : '')}</div>
        </div>
        <div className="dr-fact">
          <div className="dr-fact-label">
            <span>Schedule</span>
            <Badge tone={scheduleOn ? 'ok' : 'warn'}>{every(status?.interval_sec)}</Badge>
          </div>
          <div className="dr-fact-value">{scheduleOn && status?.next_run_at ? `Next ${when(status.next_run_at)}` : 'Manual only'}</div>
          <div className="dr-fact-note">Counts from the last attempt, successful or not</div>
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Back up now</h3>
          <div className="dr-actions">
            <button type="button" className="btn btn-primary btn-sm" onClick={runBackup} disabled={running || !canBackUp}>
              {running ? <Loader2 size={14} className="dr-spin" /> : <Send size={14} />}
              <span>{running ? 'Sealing…' : 'Back up now'}</span>
            </button>
            <button type="button" className="btn btn-secondary btn-sm" onClick={downloadCapsule} disabled={!keyPinned}>
              <Download size={14} />
              <span>Download capsule</span>
            </button>
            <button type="button" className="btn btn-secondary btn-sm" onClick={runDrill} disabled={runningDrill}>
              {runningDrill ? <Loader2 size={14} className="dr-spin" /> : <Play size={14} />}
              <span>{runningDrill ? 'Restoring…' : 'Run restore drill'}</span>
            </button>
          </div>
        </div>
        <p className="dr-hint">
          One sealed capsule goes to every destination above: the local directory, and KyRecovery when paired. Download saves
          the same capsule to this browser instead. Nothing on this server can open a capsule; that takes{' '}
          {status?.threshold ?? 'k'} custodian cards together.
        </p>
        <div className="dr-note">A capsule carries</div>
        <ul className="dr-members">
          {(status?.members ?? []).map((m) => (
            <li key={m}>{m}</li>
          ))}
        </ul>
        {runMessage && (
          <div className="alert alert-success dr-mt">
            <CheckCircle size={16} /> <span>{runMessage}</span>
          </div>
        )}
        {runError && (
          <div className="alert alert-error dr-mt">
            <XCircle size={16} /> <span>{runError}</span>
          </div>
        )}
        {copies.length > 0 && (
          <ul className="dr-copies">
            {copies.map((c) => (
              <li key={c.name}>
                <span>{c.name}</span>
                <span>
                  {bytes(c.size_bytes)} · {when(c.created_at)}
                </span>
              </li>
            ))}
          </ul>
        )}
        {drillResult && (
          <div className="dr-mt">
            <div className="dr-note">
              Restore drill <Badge tone={drillResult.passed ? 'ok' : 'off'}>{drillResult.passed ? 'passed' : 'failed'}</Badge>{' '}
              <span className="dr-muted">{drillResult.duration_ms} ms</span>
            </div>
            {drillResult.error_message && <div className="dr-danger dr-mt-sm">{drillResult.error_message}</div>}
            <div className="dr-checks">
              {drillResult.checks.map((check, idx) => (
                <div key={idx} className="dr-check">
                  {check.passed ? <CheckCircle size={14} color="var(--cyan)" /> : <XCircle size={14} color="var(--accent-red)" />}
                  <span style={{ fontWeight: 600 }}>{check.name}</span>
                  <span className="dr-muted">{check.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div style={cardStyle}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '1rem' }}>Schedule</h3>
        <form onSubmit={saveSchedule} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ marginBottom: 0, flex: 1, minWidth: '12rem' }}>
            <label className="form-label" htmlFor="backup-interval">
              Back up automatically
            </label>
            <select id="backup-interval" className="input" value={scheduleSec} onChange={(e) => setScheduleSec(Number(e.target.value))}>
              {SCHEDULE_CHOICES.map((c) => (
                <option key={c.sec} value={c.sec}>
                  {c.label}
                </option>
              ))}
            </select>
          </div>
          <button type="submit" className="btn btn-primary btn-sm" disabled={scheduleSaving || scheduleSec === (status?.interval_sec ?? -1)}>
            {scheduleSaving ? <Loader2 size={14} className="dr-spin" /> : <Clock size={14} />}
            <span>Save</span>
          </button>
        </form>
        <p className="dr-hint dr-mt">
          Each run snapshots the whole database, so the floor is {Math.round((status?.min_interval_sec ?? 900) / 60)} minutes. The
          schedule does nothing until a key is pinned and there is somewhere to send the capsule.
        </p>
        {scheduleMessage && (
          <div className="alert alert-success dr-mt">
            <CheckCircle size={16} /> <span>{scheduleMessage}</span>
          </div>
        )}
        {scheduleError && (
          <div className="alert alert-error dr-mt">
            <XCircle size={16} /> <span>{scheduleError}</span>
          </div>
        )}
      </div>

      <div className="dr-two">
        <div style={cardStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Server size={16} color="var(--cyan)" /> KyRecovery
            </h3>
            <Badge tone={paired ? 'ok' : 'off'}>{paired ? 'Paired' : 'Not paired'}</Badge>
          </div>
          <p className="dr-hint">
            KyRecovery keeps capsules it cannot open, off this host. In its dashboard, generate a pairing code for this service
            and enter it here. Pairing hands this server the suite recovery key and a deposit credential;
            {paired ? ' re-pairing is only accepted with the same key.' : ' the key is pinned once and never replaced.'}
            {status?.allow_private_recovery ? ' Private and CGNAT destinations are admitted on this server (HTTPS still required).' : ''}
          </p>
          <form onSubmit={pair}>
            <div className="form-group">
              <label className="form-label" htmlFor="recovery-url">
                Server URL
              </label>
              <input id="recovery-url" className="input" type="url" placeholder="https://recovery.example.com" value={remoteUrl} onChange={(e) => setRemoteUrl(e.target.value)} required />
            </div>
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
              <div className="form-group" style={{ marginBottom: 0, flex: 1 }}>
                <label className="form-label" htmlFor="pairing-code">
                  Pairing code
                </label>
                <input id="pairing-code" className="input input-mono" type="text" inputMode="numeric" placeholder="123456" value={pairCode} onChange={(e) => setPairCode(e.target.value)} required />
              </div>
              <button type="submit" className="btn btn-primary btn-sm" disabled={pairing}>
                {pairing ? <Loader2 size={14} className="dr-spin" /> : <Link2 size={14} />}
                <span>{paired ? 'Re-pair' : 'Pair'}</span>
              </button>
            </div>
          </form>
          {paired && (
            <button type="button" className="btn btn-secondary btn-sm dr-mt" onClick={unpair} disabled={unpairing}>
              {unpairing ? <Loader2 size={14} className="dr-spin" /> : <Unlink size={14} />}
              <span>Unpair</span>
            </button>
          )}
          {pairMessage && (
            <div className="alert alert-success dr-mt">
              <CheckCircle size={16} /> <span>{pairMessage}</span>
            </div>
          )}
          {pairError && (
            <div className="alert alert-error dr-mt">
              <XCircle size={16} /> <span>{pairError}</span>
            </div>
          )}
        </div>

        <div style={cardStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <KeyRound size={16} color="var(--cyan)" /> Recovery key by hand
            </h3>
            <Badge tone={keyPinned ? 'ok' : 'warn'}>{keyPinned ? 'Pinned' : 'None'}</Badge>
          </div>
          {keyPinned ? (
            <p className="dr-hint" style={{ marginBottom: 0 }}>
              The key is pinned{paired ? ' by pairing' : ''}. Rotating it means a new ceremony and a fresh data directory; there is
              no button for that on purpose.
            </p>
          ) : (
            <>
              <p className="dr-hint">
                For a server with no KyRecovery. Run the suite ceremony once, keep the custodian cards, and paste the public key it
                shows, with the split it used. Capsules then go to the local directory.
              </p>
              <form onSubmit={pin}>
                <div className="form-group">
                  <label className="form-label" htmlFor="pin-key">
                    Suite recovery public key
                  </label>
                  <textarea id="pin-key" className="input input-mono" rows={4} value={pinKey} onChange={(e) => setPinKey(e.target.value)} placeholder="base64 from the ceremony page" required />
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
                  <div className="form-group" style={{ marginBottom: 0, width: '6rem' }}>
                    <label className="form-label" htmlFor="pin-k">
                      Needed
                    </label>
                    <input id="pin-k" className="input" type="number" min={2} max={255} value={pinK} onChange={(e) => setPinK(e.target.value)} required />
                  </div>
                  <div className="form-group" style={{ marginBottom: 0, width: '6rem' }}>
                    <label className="form-label" htmlFor="pin-n">
                      Of
                    </label>
                    <input id="pin-n" className="input" type="number" min={2} max={255} value={pinN} onChange={(e) => setPinN(e.target.value)} required />
                  </div>
                  <div style={{ flex: 1 }} />
                  <button type="submit" className="btn btn-primary btn-sm" disabled={pinning}>
                    {pinning ? <Loader2 size={14} className="dr-spin" /> : <KeyRound size={14} />}
                    <span>Pin key</span>
                  </button>
                </div>
              </form>
              {pinError && (
                <div className="alert alert-error dr-mt">
                  <XCircle size={16} /> <span>{pinError}</span>
                </div>
              )}
            </>
          )}
          {hasLocal && (
            <p className="dr-hint dr-mt" style={{ marginBottom: 0 }}>
              <HardDrive size={12} color="var(--cyan)" /> Local copies land in {status?.local_dir}; the newest {status?.local_keep} are kept.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};
