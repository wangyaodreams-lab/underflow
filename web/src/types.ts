// Wire and plaintext types shared across the frontend.

export interface KDF {
  id: number;
  m: number;
  t: number;
  p: number;
  salt: string; // base64
}

export interface SessionInfo {
  userId: string;
  email: string;
  kdf: KDF;
  token?: string;
  csrf?: string;
}

export interface Vault {
  id: string;
  alg: number;
  nameEnc: string;
  protectedVaultKey: string;
  revision: number;
  updatedAt: number;
}

export interface RemoteItem {
  id: string;
  vaultId: string;
  revision: number;
  blob: string;
  deleted: boolean;
  updatedAt: number;
}

export interface SyncResult {
  items: RemoteItem[];
  revision: number;
}

export interface CustomField {
  name: string;
  value: string;
  type?: string;
}

export interface PasswordEntry {
  password: string;
  changedAt: string;
}

export interface Item {
  id: string;
  type: string;
  name: string;
  username?: string;
  password?: string;
  urls?: string[];
  totp?: string;
  notes?: string;
  tags?: string[];
  folder?: string;
  fields?: CustomField[];
  passwordHistory?: PasswordEntry[];
  favorite?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface DecryptedItem {
  vaultId: string;
  remote: RemoteItem;
  item: Item;
}

export function emptyItem(id: string): Item {
  const now = new Date().toISOString();
  return { id, type: "login", name: "", urls: [], createdAt: now, updatedAt: now };
}
