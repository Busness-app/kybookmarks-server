import React, { useState, useEffect, useMemo } from 'react';
import { getJSON, postJSON, toErrorMessage } from '../lib/api';
import {
  encryptVaultObject,
  decryptVaultObject,
  EncryptedEnvelope,
} from '../lib/crypto';
import {
  BookmarkFolder,
  BookmarkItem,
  parseNetscapeBookmarkHTML,
  exportToNetscapeHTML,
} from '../lib/netscape';
import {
  Folder,
  Bookmark as BookmarkIcon,
  Trash2,
  Plus,
  Search,
  Upload,
  Download,
  ExternalLink,
  Edit2,
  RotateCcw,
  Clock,
  Smartphone,
  Shield,
  RefreshCw,
  Copy,
  Check,
  AlertTriangle,
  FolderPlus,
} from 'lucide-react';

interface BookmarksPageProps {
  user: any;
  vaultKey: CryptoKey;
  onOpenPairing: () => void;
  onOpenReconciliation: (conflicts: any[]) => void;
}

export const BookmarksPage: React.FC<BookmarksPageProps> = ({
  user,
  vaultKey,
  onOpenPairing,
  onOpenReconciliation,
}) => {
  const [folders, setFolders] = useState<BookmarkFolder[]>([
    { id: 'bookmarks_bar', name: 'Bookmarks Bar', parentId: '' },
    { id: 'other_bookmarks', name: 'Other Bookmarks', parentId: '' },
    { id: 'mobile_bookmarks', name: 'Mobile Bookmarks', parentId: '' },
  ]);
  const [bookmarks, setBookmarks] = useState<BookmarkItem[]>([]);
  const [activeFolderId, setActiveFolderId] = useState<string>('bookmarks_bar');
  const [isTrashView, setIsTrashView] = useState(false);
  const [trashBookmarks, setTrashBookmarks] = useState<BookmarkItem[]>([]);

  const [searchQuery, setSearchQuery] = useState('');
  const [syncing, setSyncing] = useState(false);
  const [syncStatus, setSyncStatus] = useState<'idle' | 'syncing' | 'error' | 'success'>('idle');
  const [lastSyncTime, setLastSyncTime] = useState<Date | null>(null);

  // Modals
  const [showAddBookmark, setShowAddBookmark] = useState(false);
  const [editingBookmark, setEditingBookmark] = useState<BookmarkItem | null>(null);
  const [showAddFolder, setShowAddFolder] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [importHTML, setImportHTML] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Form states
  const [formUrl, setFormUrl] = useState('');
  const [formTitle, setFormTitle] = useState('');
  const [formNotes, setFormNotes] = useState('');
  const [formFolderId, setFormFolderId] = useState('');
  const [formFolderName, setFormFolderName] = useState('');
  const [formFolderParentId, setFormFolderParentId] = useState('');

  // 1. Initial Load & Sync
  useEffect(() => {
    handleSync();
  }, []);

  const handleSync = async () => {
    setSyncing(true);
    setSyncStatus('syncing');

    try {
      // 1. Fetch raw objects from server
      const res = await getJSON<{ objects: any[] }>('/api/vault/objects?trash=true');
      const decryptedFolders: BookmarkFolder[] = [
        { id: 'bookmarks_bar', name: 'Bookmarks Bar', parentId: '' },
        { id: 'other_bookmarks', name: 'Other Bookmarks', parentId: '' },
        { id: 'mobile_bookmarks', name: 'Mobile Bookmarks', parentId: '' },
      ];
      const decryptedBMs: BookmarkItem[] = [];
      const decryptedTrash: BookmarkItem[] = [];

      for (const obj of res.objects || []) {
        try {
          const envelope: EncryptedEnvelope = {
            ciphertext: obj.ciphertext,
            nonce: obj.nonce,
            keyWrapper: obj.keyWrapper,
          };
          const data = await decryptVaultObject(envelope, vaultKey);

          if (obj.objectType === 'folder') {
            decryptedFolders.push({
              id: obj.objectId,
              name: data.name || 'Folder',
              parentId: obj.parentId || '',
            });
          } else {
            const item: BookmarkItem = {
              id: obj.objectId,
              url: data.url || '',
              title: data.title || data.url || 'Bookmark',
              notes: data.notes || '',
              folderId: obj.parentId || 'other_bookmarks',
              position: obj.position || 0,
              icon: data.icon,
              createdAt: data.createdAt || Date.now(),
              updatedAt: data.updatedAt || Date.now(),
            };
            if (obj.deleted) {
              decryptedTrash.push(item);
            } else {
              decryptedBMs.push(item);
            }
          }
        } catch {
          // If decrypt fails on an individual item, skip
        }
      }

      setFolders(decryptedFolders);
      setBookmarks(decryptedBMs);
      setTrashBookmarks(decryptedTrash);
      setLastSyncTime(new Date());
      setSyncStatus('success');
    } catch {
      setSyncStatus('error');
    } finally {
      setSyncing(false);
    }
  };

  // Filtered bookmarks for display
  const displayedBookmarks = useMemo(() => {
    const list = isTrashView ? trashBookmarks : bookmarks;
    let filtered = list;

    if (!isTrashView && activeFolderId) {
      filtered = filtered.filter((b) => b.folderId === activeFolderId);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (b) =>
          b.title.toLowerCase().includes(q) ||
          b.url.toLowerCase().includes(q) ||
          (b.notes && b.notes.toLowerCase().includes(q))
      );
    }

    return filtered;
  }, [bookmarks, trashBookmarks, isTrashView, activeFolderId, searchQuery]);

  // Save or Update Bookmark
  const handleSaveBookmark = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formUrl) return;

    let targetUrl = formUrl.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl;
    }

    const bmId = editingBookmark ? editingBookmark.id : crypto.randomUUID();
    const folderId = formFolderId || activeFolderId || 'other_bookmarks';

    const payload = {
      url: targetUrl,
      title: formTitle.trim() || targetUrl,
      notes: formNotes.trim(),
      folderId,
      createdAt: editingBookmark ? editingBookmark.createdAt : Date.now(),
      updatedAt: Date.now(),
    };

    const envelope = await encryptVaultObject(payload, vaultKey);

    const changeObj = {
      objectId: bmId,
      objectType: 'bookmark',
      parentId: folderId,
      version: editingBookmark ? 2 : 1, // CAS version
      position: 0,
      deleted: false,
      ciphertext: envelope.ciphertext,
      nonce: envelope.nonce,
      keyWrapper: envelope.keyWrapper,
      protocolVersion: 1,
    };

    try {
      const syncResp = await postJSON<{ conflicts: any[] }>('/api/vault/sync', {
        knownVersions: { [bmId]: editingBookmark ? 1 : 0 },
        changes: [changeObj],
      });

      if (syncResp.conflicts && syncResp.conflicts.length > 0) {
        onOpenReconciliation(syncResp.conflicts);
      }

      setShowAddBookmark(false);
      setEditingBookmark(null);
      setFormUrl('');
      setFormTitle('');
      setFormNotes('');
      handleSync();
    } catch (err) {
      alert(toErrorMessage(err, 'Failed to save bookmark'));
    }
  };

  // Move to Trash or Restore
  const handleToggleTrash = async (bm: BookmarkItem, deleted: boolean) => {
    const payload = {
      url: bm.url,
      title: bm.title,
      notes: bm.notes,
      folderId: bm.folderId,
      createdAt: bm.createdAt,
      updatedAt: Date.now(),
    };
    const envelope = await encryptVaultObject(payload, vaultKey);

    const changeObj = {
      objectId: bm.id,
      objectType: 'bookmark',
      parentId: bm.folderId,
      version: 2,
      position: 0,
      deleted,
      ciphertext: envelope.ciphertext,
      nonce: envelope.nonce,
      keyWrapper: envelope.keyWrapper,
      protocolVersion: 1,
    };

    try {
      await postJSON('/api/vault/sync', {
        knownVersions: { [bm.id]: 1 },
        changes: [changeObj],
      });
      handleSync();
    } catch (err) {
      alert(toErrorMessage(err, 'Failed to update bookmark'));
    }
  };

  // Add Folder
  const handleSaveFolder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formFolderName.trim()) return;

    const folderId = crypto.randomUUID();
    const payload = {
      name: formFolderName.trim(),
      parentId: formFolderParentId || '',
    };
    const envelope = await encryptVaultObject(payload, vaultKey);

    const changeObj = {
      objectId: folderId,
      objectType: 'folder',
      parentId: formFolderParentId || '',
      version: 1,
      deleted: false,
      ciphertext: envelope.ciphertext,
      nonce: envelope.nonce,
      keyWrapper: envelope.keyWrapper,
      protocolVersion: 1,
    };

    try {
      await postJSON('/api/vault/sync', {
        knownVersions: {},
        changes: [changeObj],
      });
      setShowAddFolder(false);
      setFormFolderName('');
      setFormFolderParentId('');
      handleSync();
    } catch (err) {
      alert(toErrorMessage(err, 'Failed to create folder'));
    }
  };

  // Netscape HTML Import
  const handleImportHTMLSubmit = async () => {
    if (!importHTML) return;
    const parsed = parseNetscapeBookmarkHTML(importHTML);
    if (parsed.length === 0) {
      alert('No valid bookmarks found in HTML');
      return;
    }

    setSyncing(true);
    try {
      const changes = [];
      for (const item of parsed) {
        const bmId = crypto.randomUUID();
        const payload = {
          url: item.url,
          title: item.title,
          notes: item.notes || '',
          folderId: 'other_bookmarks',
          createdAt: item.addDate || Date.now(),
          updatedAt: Date.now(),
        };
        const env = await encryptVaultObject(payload, vaultKey);
        changes.push({
          objectId: bmId,
          objectType: 'bookmark',
          parentId: 'other_bookmarks',
          version: 1,
          deleted: false,
          ciphertext: env.ciphertext,
          nonce: env.nonce,
          keyWrapper: env.keyWrapper,
          protocolVersion: 1,
        });
      }

      // Batch upload in chunks of 50
      for (let i = 0; i < changes.length; i += 50) {
        const chunk = changes.slice(i, i + 50);
        await postJSON('/api/vault/sync', {
          knownVersions: {},
          changes: chunk,
        });
      }

      setShowImportModal(false);
      setImportHTML('');
      handleSync();
      alert(`Successfully imported ${parsed.length} bookmarks!`);
    } catch (err) {
      alert(toErrorMessage(err, 'Import failed'));
    } finally {
      setSyncing(false);
    }
  };

  // Export HTML
  const handleExportHTML = () => {
    const html = exportToNetscapeHTML(folders, bookmarks);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kybookmarks_export_${new Date().toISOString().slice(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyUrl = (id: string, url: string) => {
    navigator.clipboard.writeText(url);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  return (
    <div className="main-content">
      {/* Sidebar Folders */}
      <div className="sidebar">
        <div className="sidebar-header">
          <span className="sidebar-title">Bookmark Folders</span>
          <button
            className="icon-btn"
            onClick={() => setShowAddFolder(true)}
            title="New Folder (Max 5 Depth)"
          >
            <FolderPlus size={16} />
          </button>
        </div>

        <div className="folder-tree">
          {folders.map((f) => {
            const count = bookmarks.filter((b) => b.folderId === f.id).length;
            const isActive = !isTrashView && activeFolderId === f.id;
            return (
              <div
                key={f.id}
                className={`folder-item ${isActive ? 'active' : ''}`}
                onClick={() => {
                  setActiveFolderId(f.id);
                  setIsTrashView(false);
                }}
              >
                <div className="folder-left">
                  <Folder size={16} />
                  <span>{f.name}</span>
                </div>
                <span className="folder-badge">{count}</span>
              </div>
            );
          })}

          <div
            className={`folder-item ${isTrashView ? 'active' : ''}`}
            style={{ marginTop: 'auto', color: isTrashView ? 'var(--cyan)' : 'var(--text-muted)' }}
            onClick={() => setIsTrashView(true)}
          >
            <div className="folder-left">
              <Trash2 size={16} />
              <span>Trash (90 days)</span>
            </div>
            <span className="folder-badge">{trashBookmarks.length}</span>
          </div>
        </div>
      </div>

      {/* Main Bookmarks View */}
      <div className="view-container">
        <div className="view-header">
          <div className="search-wrap">
            <Search size={16} className="search-icon" />
            <input
              type="text"
              className="input search-input"
              placeholder="Search bookmarks (URL, title, notes)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              className="btn btn-secondary btn-sm"
              onClick={handleSync}
              disabled={syncing}
              title="Sync encrypted changes"
            >
              <RefreshCw size={14} className={syncing ? 'spin' : ''} />
              <span>{syncing ? 'Syncing...' : 'Sync'}</span>
            </button>

            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setShowImportModal(true)}
              title="Import browser HTML bookmarks"
            >
              <Upload size={14} />
              <span>Import</span>
            </button>

            <button
              className="btn btn-secondary btn-sm"
              onClick={handleExportHTML}
              title="Export standard Netscape HTML"
            >
              <Download size={14} />
              <span>Export</span>
            </button>

            <button
              className="btn btn-primary btn-sm"
              onClick={() => {
                setEditingBookmark(null);
                setFormUrl('');
                setFormTitle('');
                setFormNotes('');
                setFormFolderId(activeFolderId);
                setShowAddBookmark(true);
              }}
            >
              <Plus size={14} />
              <span>Add Bookmark</span>
            </button>
          </div>
        </div>

        {/* Bookmarks Grid */}
        <div className="bookmarks-scroll">
          {displayedBookmarks.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '4rem 1rem', color: 'var(--text-muted)' }}>
              <BookmarkIcon size={48} style={{ opacity: 0.2, marginBottom: '1rem' }} />
              <p style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                {isTrashView ? 'Trash is empty' : 'No bookmarks found'}
              </p>
              <p style={{ fontSize: '0.85rem', marginTop: '0.25rem' }}>
                {isTrashView
                  ? 'Items deleted in the last 90 days appear here.'
                  : 'Click "+ Add Bookmark" or "Import" to organize your secure bookmarks.'}
              </p>
            </div>
          ) : (
            <div className="bookmarks-grid">
              {displayedBookmarks.map((bm) => (
                <div key={bm.id} className="bookmark-card">
                  <div className="bm-header">
                    <div className="bm-favicon">
                      <BookmarkIcon size={14} color="var(--cyan)" />
                    </div>
                    <div className="bm-title-wrap">
                      <div className="bm-title" title={bm.title}>
                        {bm.title}
                      </div>
                      <a
                        href={bm.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="bm-url"
                        title={bm.url}
                      >
                        {bm.url.replace(/^https?:\/\//, '')}
                      </a>
                    </div>
                  </div>

                  {bm.notes && <div className="bm-notes">{bm.notes}</div>}

                  <div className="bm-footer">
                    <span>{new Date(bm.createdAt).toLocaleDateString()}</span>
                    <div className="bm-actions">
                      <button
                        className="icon-btn"
                        onClick={() => copyUrl(bm.id, bm.url)}
                        title="Copy URL"
                      >
                        {copiedId === bm.id ? <Check size={14} color="var(--accent-green)" /> : <Copy size={14} />}
                      </button>

                      <a
                        href={bm.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="icon-btn"
                        title="Open Link"
                      >
                        <ExternalLink size={14} />
                      </a>

                      {!isTrashView ? (
                        <>
                          <button
                            className="icon-btn"
                            onClick={() => {
                              setEditingBookmark(bm);
                              setFormUrl(bm.url);
                              setFormTitle(bm.title);
                              setFormNotes(bm.notes || '');
                              setFormFolderId(bm.folderId);
                              setShowAddBookmark(true);
                            }}
                            title="Edit"
                          >
                            <Edit2 size={14} />
                          </button>

                          <button
                            className="icon-btn danger"
                            onClick={() => handleToggleTrash(bm, true)}
                            title="Move to Trash"
                          >
                            <Trash2 size={14} />
                          </button>
                        </>
                      ) : (
                        <button
                          className="icon-btn"
                          onClick={() => handleToggleTrash(bm, false)}
                          title="Restore from Trash"
                        >
                          <RotateCcw size={14} />
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Add / Edit Bookmark Modal */}
      {showAddBookmark && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="modal-header">
              <h3 className="modal-title">
                {editingBookmark ? 'Edit Bookmark' : 'Add New Bookmark'}
              </h3>
              <button
                className="icon-btn"
                onClick={() => {
                  setShowAddBookmark(false);
                  setEditingBookmark(null);
                }}
              >
                ✕
              </button>
            </div>
            <form onSubmit={handleSaveBookmark}>
              <div className="modal-body">
                <div className="form-group">
                  <label className="form-label">URL</label>
                  <input
                    type="text"
                    className="input input-mono"
                    placeholder="https://example.com"
                    value={formUrl}
                    onChange={(e) => setFormUrl(e.target.value)}
                    required
                    autoFocus
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Title</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="e.g. GitHub Repository"
                    value={formTitle}
                    onChange={(e) => setFormTitle(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Folder</label>
                  <select
                    className="input"
                    value={formFolderId}
                    onChange={(e) => setFormFolderId(e.target.value)}
                  >
                    {folders.map((f) => (
                      <option key={f.id} value={f.id}>
                        {f.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Notes & Description</label>
                  <textarea
                    className="input"
                    rows={3}
                    placeholder="Optional encrypted notes..."
                    value={formNotes}
                    onChange={(e) => setFormNotes(e.target.value)}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => {
                    setShowAddBookmark(false);
                    setEditingBookmark(null);
                  }}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  <span>Save Bookmark</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Folder Modal */}
      {showAddFolder && (
        <div className="modal-overlay">
          <div className="modal-card">
            <div className="modal-header">
              <h3 className="modal-title">New Folder</h3>
              <button className="icon-btn" onClick={() => setShowAddFolder(false)}>
                ✕
              </button>
            </div>
            <form onSubmit={handleSaveFolder}>
              <div className="modal-body">
                <div className="form-group">
                  <label className="form-label">Folder Name</label>
                  <input
                    type="text"
                    className="input"
                    placeholder="e.g. Work Projects"
                    value={formFolderName}
                    onChange={(e) => setFormFolderName(e.target.value)}
                    required
                    autoFocus
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Parent Folder (Max Depth 5)</label>
                  <select
                    className="input"
                    value={formFolderParentId}
                    onChange={(e) => setFormFolderParentId(e.target.value)}
                  >
                    <option value="">(Root)</option>
                    {folders.map((f) => (
                      <option key={f.id} value={f.id}>
                        {f.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowAddFolder(false)}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  <span>Create Folder</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Import HTML Modal */}
      {showImportModal && (
        <div className="modal-overlay">
          <div className="modal-card" style={{ maxWidth: '600px' }}>
            <div className="modal-header">
              <h3 className="modal-title">Import Browser Bookmarks</h3>
              <button className="icon-btn" onClick={() => setShowImportModal(false)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                Select an exported Netscape Bookmark HTML file from Chrome, Firefox, Safari, Edge, or Brave:
              </p>

              <div className="form-group">
                <input
                  type="file"
                  accept=".html,.htm"
                  className="input"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      const reader = new FileReader();
                      reader.onload = (ev) => setImportHTML((ev.target?.result as string) || '');
                      reader.readAsText(file);
                    }
                  }}
                />
              </div>

              {importHTML && (
                <div className="alert alert-success">
                  <Check size={16} />
                  <span>HTML file loaded ({Math.round(importHTML.length / 1024)} KB)</span>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setShowImportModal(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleImportHTMLSubmit}
                disabled={!importHTML || syncing}
              >
                <Upload size={14} />
                <span>Import Bookmarks</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
