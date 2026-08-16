// Web Crypto API helpers for Zero-Knowledge End-to-End Encryption

export interface EncryptedEnvelope {
  ciphertext: string; // base64
  nonce: string;      // base64 (12 bytes for AES-GCM)
  keyWrapper: string; // base64 wrapped object key
}

export function generateRandomHex(lengthBytes: number): string {
  const bytes = new Uint8Array(lengthBytes);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generatePaperRecoveryKey(): string {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  let res = '';
  for (let i = 0; i < bytes.length; i++) {
    if (i > 0 && i % 4 === 0) res += '-';
    res += charset[bytes[i] % charset.length];
  }
  return res;
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Derive a 256-bit AES-GCM key from password and salt
export async function deriveKeyFromPassword(
  pass: string,
  saltHex: string,
  iterations: number = 600000
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(pass),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: hexToBytes(saltHex) as any,
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

// Generate a random 256-bit vault master key
export async function generateVaultKey(): Promise<CryptoKey> {
  return window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

// Wrap (encrypt) the vault key under a password/recovery key
export async function wrapVaultKey(vaultKey: CryptoKey, wrappingKey: CryptoKey): Promise<string> {
  const iv = new Uint8Array(12);
  window.crypto.getRandomValues(iv);

  const wrapped = await window.crypto.subtle.wrapKey(
    'raw',
    vaultKey,
    wrappingKey,
    { name: 'AES-GCM', iv }
  );

  const combined = new Uint8Array(iv.length + wrapped.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(wrapped), iv.length);
  return bytesToBase64(combined);
}

// Unwrap (decrypt) the vault key
export async function unwrapVaultKey(wrappedBase64: string, unwrappingKey: CryptoKey): Promise<CryptoKey> {
  const rawCombined = base64ToBytes(wrappedBase64);
  const iv = rawCombined.slice(0, 12);
  const wrapped = rawCombined.slice(12);

  return window.crypto.subtle.unwrapKey(
    'raw',
    wrapped,
    unwrappingKey,
    { name: 'AES-GCM', iv: iv as any },
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

// Export raw vault key to base64 for sessionStorage
export async function exportVaultKeyRaw(vaultKey: CryptoKey): Promise<string> {
  const raw = await window.crypto.subtle.exportKey('raw', vaultKey);
  return bytesToBase64(new Uint8Array(raw));
}

// Import raw vault key from base64
export async function importVaultKeyRaw(rawBase64: string): Promise<CryptoKey> {
  const rawBytes = base64ToBytes(rawBase64);
  return window.crypto.subtle.importKey(
    'raw',
    rawBytes as any,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

// Encrypt an object (bookmark/folder) using per-object key wrapped under vault key
export async function encryptVaultObject(
  data: any,
  vaultKey: CryptoKey
): Promise<EncryptedEnvelope> {
  // 1. Generate random 256-bit object key
  const objectKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  // 2. Encrypt payload with object key
  const iv = new Uint8Array(12);
  window.crypto.getRandomValues(iv);
  const jsonBytes = new TextEncoder().encode(JSON.stringify(data));
  const encryptedPayload = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    objectKey,
    jsonBytes
  );

  // 3. Wrap object key with vault key
  const keyWrapper = await wrapVaultKey(objectKey, vaultKey);

  return {
    ciphertext: bytesToBase64(new Uint8Array(encryptedPayload)),
    nonce: bytesToBase64(iv),
    keyWrapper,
  };
}

// Decrypt an object payload
export async function decryptVaultObject<T = any>(
  envelope: EncryptedEnvelope,
  vaultKey: CryptoKey
): Promise<T> {
  // 1. Unwrap per-object key
  const objectKey = await unwrapVaultKey(envelope.keyWrapper, vaultKey);

  // 2. Decrypt payload
  const iv = base64ToBytes(envelope.nonce);
  const ciphertext = base64ToBytes(envelope.ciphertext);

  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as any },
    objectKey,
    ciphertext as any
  );

  const jsonStr = new TextDecoder().decode(decrypted);
  return JSON.parse(jsonStr) as T;
}

// Client-side authentication secret derivation
export async function deriveAuthSecret(password: string, saltHex: string, iterations: number = 600000): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: hexToBytes(saltHex) as any,
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  return bytesToHex(new Uint8Array(derivedBits));
}
