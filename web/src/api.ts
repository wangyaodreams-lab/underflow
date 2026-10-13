// Minimal JSON client for the Underflow API. Uses cookie sessions and the
// double-submit CSRF token.

import type { KDF, RemoteItem, SessionInfo, SyncResult, Vault } from "./types";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)uf_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "X-UF-Client": "web" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD") {
    const t = csrfToken();
    if (t) headers["X-UF-CSRF"] = t;
  }
  const resp = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await resp.text();
  if (!resp.ok) {
    let code = "";
    let message = text;
    try {
      const parsed = JSON.parse(text);
      code = parsed?.error?.code ?? "";
      message = parsed?.error?.message ?? text;
    } catch {
      /* keep raw text */
    }
    throw new ApiError(resp.status, code, message);
  }
  return (text ? JSON.parse(text) : undefined) as T;
}

export interface RegisterPayload {
  email: string;
  kdf: KDF;
  authKey: string;
  vaultId: string;
  alg: number;
  vaultNameEnc: string;
  protectedVaultKey: string;
}

export interface VaultKeyPayload {
  id: string;
  alg: number;
  protectedVaultKey: string;
}

export const api = {
  kdf: (email: string) => request<{ kdf: KDF }>("GET", `/api/v1/auth/kdf?email=${encodeURIComponent(email)}`),
  register: (p: RegisterPayload) => request<SessionInfo>("POST", "/api/v1/auth/register", p),
  login: (email: string, authKey: string) =>
    request<SessionInfo>("POST", "/api/v1/auth/login", { email, authKey }),
  logout: () => request<{ ok: boolean }>("POST", "/api/v1/auth/logout"),
  me: () => request<SessionInfo>("GET", "/api/v1/user"),
  listVaults: () => request<{ vaults: Vault[] }>("GET", "/api/v1/vaults"),
  createItem: (vaultId: string, id: string, blob: string) =>
    request<RemoteItem>("POST", `/api/v1/vaults/${vaultId}/items`, { id, blob }),
  updateItem: (vaultId: string, itemId: string, blob: string, baseRevision: number) =>
    request<RemoteItem>("PUT", `/api/v1/vaults/${vaultId}/items/${itemId}`, { blob, baseRevision }),
  deleteItem: (vaultId: string, itemId: string, revision: number) =>
    request<RemoteItem>("DELETE", `/api/v1/vaults/${vaultId}/items/${itemId}?revision=${revision}`),
  sync: (since: number) => request<SyncResult>("GET", `/api/v1/sync?since=${since}`),
  changePassword: (kdf: KDF, authKey: string, vaults: VaultKeyPayload[]) =>
    request<{ ok: boolean }>("POST", "/api/v1/auth/password", { kdf, authKey, vaults }),
};
