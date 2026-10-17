// Entry point for the launcher UI: wires the configuration form to the
// launcher's control API and renders live process state.

import * as api from "./api.js";
import type { Bootstrap, PepperStatus, Result, State, Status } from "./api-types.js";
import { buildForm, type FormHandle } from "./form.js";
import { buildLogView } from "./logs.js";

const POLL_ACTIVE_MS = 1500;
const POLL_IDLE_MS = 4000;

interface Elements {
  header: HTMLElement;
  statusBar: HTMLElement;
  consoleCard: HTMLElement;
  statusDot: HTMLElement;
  statusText: HTMLElement;
  statusDetail: HTMLElement;
  startBtn: HTMLButtonElement;
  stopBtn: HTMLButtonElement;
  restartBtn: HTMLButtonElement;
  openBtn: HTMLAnchorElement;
  saveBtn: HTMLButtonElement;
  pepperState: HTMLElement;
  pepperActions: HTMLElement;
  toast: HTMLElement;
  subtitle: HTMLElement;
}

interface Handlers {
  onSave(): void;
  onStart(): void;
  onStop(): void;
  onRestart(): void;
  onAutoscroll(on: boolean): void;
  onClearLogs(): void;
}

/** Builds the static chrome once; the app only mutates the returned nodes. */
function buildChrome(h: Handlers): Elements {
  const header = document.createElement("header");
  const brand = document.createElement("div");
  brand.className = "brand";
  brand.append(el("span", "logo", "U"), el("strong", "", "Underflow launcher"));
  header.append(brand);
  const subtitle = el("span", "subtitle", "");
  header.append(subtitle);

  const statusBar = document.createElement("div");
  statusBar.className = "status-bar";
  const status = document.createElement("div");
  status.className = "status";
  const statusDot = el("span", "dot");
  const statusText = el("span", "status-text", "stopped");
  status.append(statusDot, statusText);
  const statusDetail = el("span", "status-detail", "");

  const openBtn = document.createElement("a");
  openBtn.className = "button ghost";
  openBtn.textContent = "Open app";
  openBtn.target = "_blank";
  openBtn.rel = "noreferrer noopener";
  openBtn.setAttribute("aria-disabled", "true");

  const saveBtn = button("Save", "ghost", h.onSave);
  const startBtn = button("Start server", "primary", h.onStart);
  const stopBtn = button("Stop", "ghost", h.onStop);
  const restartBtn = button("Restart", "ghost", h.onRestart);

  statusBar.append(
    status,
    statusDetail,
    el("span", "spacer"),
    openBtn,
    saveBtn,
    startBtn,
    stopBtn,
    restartBtn,
  );

  const consoleCard = document.createElement("section");
  consoleCard.className = "card run-card";
  const heading = document.createElement("div");
  heading.className = "card-heading";
  heading.append(el("h2", "", "Server output"));

  const tools = document.createElement("div");
  tools.className = "log-tools";
  const followLabel = document.createElement("label");
  followLabel.className = "inline-check";
  const autoscroll = document.createElement("input");
  autoscroll.type = "checkbox";
  autoscroll.checked = true;
  autoscroll.addEventListener("change", () => h.onAutoscroll(autoscroll.checked));
  followLabel.append(autoscroll, document.createTextNode("follow"));
  tools.append(followLabel, button("Clear", "ghost small", h.onClearLogs));
  heading.append(tools);

  const pepperState = el("div", "pepper-state");
  const pepperActions = el("div", "pepper-actions");
  consoleCard.append(heading, pepperState, pepperActions);

  const toast = el("div", "toast");

  return {
    header,
    statusBar,
    consoleCard,
    statusDot,
    statusText,
    statusDetail,
    openBtn,
    saveBtn,
    startBtn,
    stopBtn,
    restartBtn,
    pepperState,
    pepperActions,
    toast,
    subtitle,
  };
}

class LauncherApp {
  private form: FormHandle;
  private logs = buildLogView();
  private els: Elements;
  private stream: EventSource | null = null;
  private pollTimer: number | null = null;
  private lastStatus: Status = "stopped";
  private busy = false;

  constructor(boot: Bootstrap) {
    this.form = buildForm(boot.spec);
    this.els = buildChrome({
      onSave: () => void this.saveOnly(),
      onStart: () => void this.start(),
      onStop: () => void this.stop(),
      onRestart: () => void this.restart(),
      onAutoscroll: (on) => this.logs.setAutoscroll(on),
      onClearLogs: () => this.logs.clear(),
    });
    this.form.showIssues(boot.result.issues);
    this.form.showDerived(derivedInfo(boot.result));
    this.renderPepper(boot.pepper);
    this.applyState(boot.state);
  }

  mount(target: HTMLElement) {
    // Layout: chrome on top, form and logs side by side.
    const layout = document.createElement("div");
    layout.className = "layout";

    const left = document.createElement("div");
    left.className = "pane pane-form";
    left.append(this.form.root);

    const right = document.createElement("div");
    right.className = "pane pane-run";
    right.append(this.els.consoleCard, this.logs.root);

    layout.append(left, right);

    const shell = document.createElement("div");
    shell.className = "shell";
    shell.append(this.els.header, this.els.statusBar, layout, this.els.toast);

    target.replaceChildren(shell);
    this.startStream();
    this.schedulePoll();
  }

  // --- actions ------------------------------------------------------------

  private setBusy(on: boolean) {
    this.busy = on;
    this.els.startBtn.disabled = on;
    this.els.restartBtn.disabled = on;
    this.els.stopBtn.disabled = on;
    this.els.saveBtn.disabled = on;
  }

  private async saveOnly() {
    if (this.busy) return;
    this.setBusy(true);
    try {
      const res = await api.saveSpec(this.form.get());
      this.form.set(res.spec);
      this.form.showIssues(res.result.issues);
      this.form.showDerived(derivedInfo(res.result));
      this.renderPepper(res.pepper);
      this.toast(res.saved ? "Configuration saved" : "Not saved: fix the problems first");
    } catch (err) {
      this.fail(err);
    } finally {
      this.setBusy(false);
    }
  }

  private async start() {
    if (this.busy) return;
    this.setBusy(true);
    try {
      this.logs.clear();
      const res = await api.start(this.form.get());
      if (res.error) {
        this.toast(res.error, true);
        this.logs.append(0, "error: " + res.error);
      } else {
        this.toast("Server starting…");
      }
      this.applyState(res.state);
    } catch (err) {
      this.fail(err);
    } finally {
      this.setBusy(false);
    }
  }

  private async stop() {
    if (this.busy) return;
    this.setBusy(true);
    try {
      const res = await api.stop();
      this.applyState(res.state);
      this.toast("Server stopped");
    } catch (err) {
      this.fail(err);
    } finally {
      this.setBusy(false);
    }
  }

  private async restart() {
    if (this.busy) return;
    this.setBusy(true);
    try {
      this.logs.clear();
      const res = await api.restart(this.form.get());
      if (res.error) {
        this.toast(res.error, true);
        this.logs.append(0, "error: " + res.error);
      } else {
        this.toast("Server restarting…");
      }
      this.applyState(res.state);
    } catch (err) {
      this.fail(err);
    } finally {
      this.setBusy(false);
    }
  }

  private async regeneratePepper(overwrite: boolean) {
    if (this.busy) return;
    if (
      overwrite &&
      !window.confirm(
        "Replace the existing server pepper?\n\nEvery existing account will be locked out and can only recover with a backup of the old pepper file.",
      )
    ) {
      return;
    }
    this.setBusy(true);
    try {
      const res = await api.rekey(this.form.get(), overwrite);
      this.renderPepper(res.pepper);
      this.toast("Pepper written to " + res.pepper.path);
      void this.refresh();
    } catch (err) {
      this.fail(err);
    } finally {
      this.setBusy(false);
    }
  }

  // --- live state ---------------------------------------------------------

  private startStream() {
    this.stream?.close();
    this.stream = api.streamLogs((line) => this.logs.append(line.seq, line.text));
  }

  private schedulePoll() {
    if (this.pollTimer !== null) window.clearTimeout(this.pollTimer);
    const delay =
      this.lastStatus === "running" || this.lastStatus === "starting" ? POLL_ACTIVE_MS : POLL_IDLE_MS;
    this.pollTimer = window.setTimeout(() => void this.refresh(), delay);
  }

  private async refresh() {
    try {
      const res = await api.state();
      this.applyState(res.state);
      this.renderPepper(res.pepper);
      if (idle(res.state.status)) {
        this.form.showIssues(res.result.issues);
        this.form.showDerived(derivedInfo(res.result));
      }
    } catch {
      // The launcher itself may be shutting down; the next poll will retry.
    } finally {
      this.schedulePoll();
    }
  }

  private applyState(state: State) {
    this.lastStatus = state.status;
    const dot = this.els.statusDot;
    dot.className = "dot " + state.status;
    dot.setAttribute("title", state.status);
    this.els.statusText.textContent = state.status;

    const bits: string[] = [];
    if (state.pid > 0 && !idle(state.status)) bits.push(`pid ${state.pid}`);
    if (state.startedAt && !idle(state.status)) {
      const up = Math.max(0, (Date.now() - Date.parse(state.startedAt)) / 1000);
      bits.push(`up ${formatDuration(up)}`);
    }
    if (state.error) bits.push(state.error);
    this.els.statusDetail.textContent = bits.join(" · ");
    this.els.statusDetail.classList.toggle("error", Boolean(state.error));

    const running = !idle(state.status);
    this.els.startBtn.textContent = running ? "Apply & restart" : "Start server";
    this.els.openBtn.href = state.url || "#";
    this.els.openBtn.classList.toggle("disabled", !state.started);
    this.els.openBtn.setAttribute("aria-disabled", String(!state.started));
    if (state.url) this.els.subtitle.textContent = state.url;
  }

  private renderPepper(pepper: PepperStatus) {
    const exists = pepper.exists;
    const detail = exists
      ? `${pepper.path} · ${pepper.size} bytes · fingerprint ${pepper.fingerprint}`
      : pepper.path
        ? `not created yet: ${pepper.path}`
        : "no pepper file path configured";
    this.els.pepperState.replaceChildren(
      el("span", exists ? "badge ok" : "badge", exists ? "pepper ready" : "pepper missing"),
      document.createTextNode(" " + detail),
    );
    if (pepper.readError) {
      this.els.pepperState.append(el("span", "error", " (" + pepper.readError + ")"));
    }

    this.els.pepperActions.replaceChildren();
    const generate = button(exists ? "Replace pepper…" : "Generate pepper", "ghost small", () =>
      void this.regeneratePepper(exists),
    );
    this.els.pepperActions.append(generate);
  }

  private toast(message: string, isError = false) {
    const node = this.els.toast;
    node.textContent = message;
    node.classList.toggle("error", isError);
    node.classList.add("show");
    window.setTimeout(() => node.classList.remove("show"), 4000);
  }

  private fail(err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    this.toast(message, true);
    this.logs.append(0, "error: " + message);
  }
}

function idle(status: Status): boolean {
  return status === "stopped" || status === "exited" || status === "failed";
}

function derivedInfo(result: Result) {
  return {
    command: result.command,
    url: result.url,
    probeUrl: result.probeUrl,
    pepperPath: result.pepperPath,
    ready: result.ready,
  };
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m ${Math.floor(seconds % 60)}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function button(label: string, className: string, onClick: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "button " + className;
  b.textContent = label;
  b.addEventListener("click", onClick);
  return b;
}

function el(tag: string, className: string, text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function main() {
  const target = document.getElementById("app");
  if (!target) return;
  try {
    const boot = await api.bootstrap();
    const app = new LauncherApp(boot);
    app.mount(target);

    // Ctrl/Cmd+Enter starts the server from anywhere in the form.
    window.addEventListener("keydown", (ev) => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") {
        ev.preventDefault();
        document.querySelector<HTMLButtonElement>(".status-bar .primary")?.click();
      }
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    target.replaceChildren(el("div", "fatal", "Could not reach the launcher: " + message));
  }
}

void main();
