// Typed wrapper around the Go crypto core compiled to js/wasm.

import type { KDF } from "./types";

export interface UnderflowWasm {
  deriveMasterKey(password: string, kdfJson: string): string;
  deriveAuthKey(masterKeyB64: string, saltB64: string): string;
  deriveKEK(masterKeyB64: string, saltB64: string): string;
  wrapVaultKey(kekB64: string, alg: number, kdfJson: string, vaultId: string, vaultKeyB64: string): string;
  unwrapVaultKey(kekB64: string, vaultId: string, protectedB64: string): string;
  sealVaultName(alg: number, vaultKeyB64: string, vaultId: string, name: string): string;
  openVaultName(vaultKeyB64: string, vaultId: string, encB64: string): string;
  sealItem(alg: number, vaultKeyB64: string, vaultId: string, itemId: string, plaintext: string): string;
  openItem(vaultKeyB64: string, vaultId: string, itemId: string, blobB64: string): string;
  randomBytes(n: number): string;
  generatePassword(optsJson: string): string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  interface Window { Go?: any; underflow?: UnderflowWasm }
}

let cached: UnderflowWasm | null = null;

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(`failed to load ${src}`));
    document.head.appendChild(s);
  });
}

async function instantiate(): Promise<{ go: unknown; instance: WebAssembly.Instance }> {
  const go = new window.Go!();
  try {
    const result = await WebAssembly.instantiateStreaming(fetch("/underflow.wasm"), go.importObject);
    return { go, instance: result.instance };
  } catch {
    // Fall back for servers that do not send application/wasm.
    const buf = await (await fetch("/underflow.wasm")).arrayBuffer();
    const result = await WebAssembly.instantiate(buf, go.importObject);
    return { go, instance: result.instance };
  }
}

function waitForApi(timeoutMs = 15000): Promise<UnderflowWasm> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (window.underflow) return resolve(window.underflow);
      if (Date.now() - start > timeoutMs) return reject(new Error("wasm core did not initialise"));
      setTimeout(tick, 25);
    };
    tick();
  });
}

export async function loadWasm(): Promise<UnderflowWasm> {
  if (cached) return cached;
  if (!window.Go) await loadScript("/wasm_exec.js");
  const { go, instance } = await instantiate();
  // go.run never resolves (the Go program blocks); do not await it.
  (go as { run(i: WebAssembly.Instance): void }).run(instance);
  cached = await waitForApi();
  return cached;
}

export function kdfJson(kdf: KDF): string {
  return JSON.stringify(kdf);
}
