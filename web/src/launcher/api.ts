// Thin fetch wrappers around the launcher's control API.

import type {
  Bootstrap,
  LogLine,
  PepperStatus,
  Spec,
  SpecResponse,
  State,
  StateResponse,
} from "./api-types.js";

interface ApiError {
  error?: { code: string; message: string };
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(`${res.status} ${res.statusText}: ${text.slice(0, 200)}`);
    }
  }
  if (!res.ok) {
    const detail = (body as ApiError | null)?.error;
    throw new Error(detail ? detail.message : `${res.status} ${res.statusText}`);
  }
  return body as T;
}

export function bootstrap(): Promise<Bootstrap> {
  return request<Bootstrap>("/api/bootstrap");
}

/** Validate a spec, and optionally persist it. */
export function saveSpec(spec: Spec): Promise<SpecResponse> {
  return request<SpecResponse>("/api/spec", {
    method: "POST",
    body: JSON.stringify({ spec }),
  });
}

export interface StartResponse {
  state: State;
  error?: string;
}

export function start(spec: Spec): Promise<StartResponse> {
  return request<StartResponse>("/api/start", {
    method: "POST",
    body: JSON.stringify({ spec }),
  });
}

export function restart(spec: Spec): Promise<StartResponse> {
  return request<StartResponse>("/api/restart", {
    method: "POST",
    body: JSON.stringify({ spec }),
  });
}

export function stop(): Promise<{ state: State }> {
  return request<{ state: State }>("/api/stop", { method: "POST", body: "{}" });
}

export function state(): Promise<StateResponse> {
  return request<StateResponse>("/api/state");
}

export function rekey(
  spec: Spec,
  overwrite: boolean,
): Promise<{ pepper: PepperStatus }> {
  return request<{ pepper: PepperStatus }>("/api/pepper", {
    method: "POST",
    body: JSON.stringify({ spec, overwrite }),
  });
}

/**
 * Subscribe to server output. The browser reconnects on its own and replays
 * from the last seen id, so no manual retry logic is needed.
 */
export function streamLogs(onLine: (line: LogLine) => void): EventSource {
  const source = new EventSource("/api/logs");
  source.onmessage = (ev) => {
    const seq = Number(ev.lastEventId || "0");
    try {
      onLine({ seq, text: JSON.parse(ev.data) as string });
    } catch {
      onLine({ seq, text: ev.data });
    }
  };
  return source;
}
