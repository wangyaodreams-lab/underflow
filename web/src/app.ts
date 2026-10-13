// Application state and crypto orchestration. Key material is held in memory
// only and cleared on lock; nothing sensitive is written to storage.

import { api, type VaultKeyPayload } from "./api";
import { kdfJson, loadWasm, type UnderflowWasm } from "./wasm";
import type { DecryptedItem, Item, KDF, Vault } from "./types";

const ALG = 1;

export class App {
  wasm!: UnderflowWasm;
  email = "";
  userId = "";
  kdf: KDF | null = null;

  // In-memory secrets (never persisted).
  private kek: string | null = null;
  private vaultKeys = new Map<string, string>();

  vaults: Vault[] = [];
  items: DecryptedItem[] = [];
  lastRevision = 0;

  locked = true;
  autoLockMinutes = 10;
  onLock: (() => void) | null = null;

  private timer: number | undefined;

  async init(): Promise<void> {
    this.wasm = await loadWasm();
    window.addEventListener("pointerdown", () => this.touch());
    window.addEventListener("keydown", () => this.touch());
    try {
      const me = await api.me();
      this.email = me.email;
      this.userId = me.userId;
      this.kdf = me.kdf;
    } catch {
      /* not authenticated yet */
    }
  }

  // --- authentication ---

  async register(email: string, password: string): Promise<void> {
    const salt = this.wasm.randomBytes(16);
    const kdf: KDF = { id: 1, m: 65536, t: 3, p: 4, salt };
    const { authKey, kek } = this.derive(password, kdf);
    const vaultId = crypto.randomUUID();
    const vaultKey = this.wasm.randomBytes(32);
    const protectedVaultKey = this.wasm.wrapVaultKey(kek, ALG, kdfJson(kdf), vaultId, vaultKey);
    const vaultNameEnc = this.wasm.sealVaultName(ALG, vaultKey, vaultId, "Default");
    await api.register({
      email,
      kdf,
      authKey,
      vaultId,
      alg: ALG,
      vaultNameEnc,
      protectedVaultKey,
    });
    this.email = email;
    this.kdf = kdf;
    this.kek = kek;
    this.vaultKeys.set(vaultId, vaultKey);
    this.vaults = [];
    this.items = [];
    this.unlockSession();
  }

  async login(email: string, password: string): Promise<void> {
    const { kdf } = await api.kdf(email);
    const { authKey, kek } = this.derive(password, kdf);
    await api.login(email, authKey);
    this.email = email;
    this.kdf = kdf;
    this.kek = kek;
    await this.loadVaults();
    await this.sync();
    this.unlockSession();
  }

  private derive(password: string, kdf: KDF) {
    const mk = this.wasm.deriveMasterKey(password, kdfJson(kdf));
    const authKey = this.wasm.deriveAuthKey(mk, kdf.salt);
    const kek = this.wasm.deriveKEK(mk, kdf.salt);
    return { mk, authKey, kek };
  }

  private async loadVaults(): Promise<void> {
    const { vaults } = await api.listVaults();
    this.vaults = vaults;
    this.vaultKeys.clear();
    for (const v of vaults) {
      const key = this.wasm.unwrapVaultKey(this.kek!, v.id, v.protectedVaultKey);
      this.vaultKeys.set(v.id, key);
    }
  }

  async sync(): Promise<void> {
    const result = await api.sync(0);
    const out: DecryptedItem[] = [];
    for (const remote of result.items) {
      if (remote.deleted) continue;
      const vk = this.vaultKeys.get(remote.vaultId);
      if (!vk) continue;
      const plain = this.wasm.openItem(vk, remote.vaultId, remote.id, remote.blob);
      out.push({ vaultId: remote.vaultId, remote, item: JSON.parse(plain) as Item });
    }
    this.items = out;
    this.lastRevision = result.revision;
  }

  // --- item operations ---

  async saveItem(item: Item): Promise<void> {
    const vaultId = this.vaultKeys.keys().next().value as string;
    const vk = this.vaultKeys.get(vaultId);
    if (!vk) throw new Error("vault is locked");
    item.updatedAt = new Date().toISOString();
    const plain = JSON.stringify(item);
    const blob = this.wasm.sealItem(ALG, vk, vaultId, item.id, plain);
    const existing = this.items.find((d) => d.item.id === item.id);
    if (existing) {
      await api.updateItem(vaultId, item.id, blob, existing.remote.revision);
    } else {
      await api.createItem(vaultId, item.id, blob);
    }
    await this.sync();
  }

  async deleteItem(id: string): Promise<void> {
    const di = this.items.find((d) => d.item.id === id);
    if (!di) return;
    await api.deleteItem(di.vaultId, di.item.id, di.remote.revision);
    await this.sync();
  }

  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    if (!this.email) throw new Error("not logged in");
    // Re-derive from the server's current parameters to verify the old password.
    const current = await api.kdf(this.email);
    const old = this.derive(oldPassword, current.kdf);
    if (!this.kek || old.kek !== this.kek) {
      // Fall back to verifying by unwrapping.
      for (const v of this.vaults) {
        this.wasm.unwrapVaultKey(old.kek, v.id, v.protectedVaultKey);
      }
    }
    const salt = this.wasm.randomBytes(16);
    const kdf: KDF = { id: 1, m: 65536, t: 3, p: 4, salt };
    const next = this.derive(newPassword, kdf);
    const payload: VaultKeyPayload[] = this.vaults.map((v) => {
      const vk = this.vaultKeys.get(v.id)!;
      return { id: v.id, alg: v.alg, protectedVaultKey: this.wasm.wrapVaultKey(next.kek, v.alg, kdfJson(kdf), v.id, vk) };
    });
    await api.changePassword(kdf, next.authKey, payload);
    this.kdf = kdf;
    this.kek = next.kek;
  }

  generatePassword(length: number): string {
    return this.wasm.generatePassword(
      JSON.stringify({ length, lower: true, upper: true, digits: true, symbols: true, excludeAmbiguous: true }),
    );
  }

  // --- lock lifecycle ---

  private unlockSession(): void {
    this.locked = false;
    this.touch();
  }

  touch(): void {
    if (this.locked) return;
    if (this.timer) window.clearTimeout(this.timer);
    this.timer = window.setTimeout(() => this.lock(), this.autoLockMinutes * 60_000);
  }

  setAutoLock(minutes: number): void {
    this.autoLockMinutes = Math.max(1, minutes);
    this.touch();
  }

  lock(): void {
    this.kek = null;
    this.vaultKeys.clear();
    this.items = [];
    this.locked = true;
    if (this.timer) window.clearTimeout(this.timer);
    this.onLock?.();
  }

  async logout(): Promise<void> {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    this.lock();
    this.email = "";
    this.userId = "";
    this.kdf = null;
  }
}
