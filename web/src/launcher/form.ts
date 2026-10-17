// The configuration form: a declarative field list rendered once, with typed
// get/set access to a Spec so the rest of the app never touches the DOM.

import type { Issue, Spec } from "./api-types.js";

export interface FormHandle {
  root: HTMLElement;
  get(): Spec;
  set(spec: Spec): void;
  /** Attach validation issues to their fields and list them in the panel. */
  showIssues(issues: Issue[] | null): void;
  /** Update the derived-command preview and pepper path hints. */
  showDerived(info: {
    command: string;
    url: string;
    probeUrl: string;
    pepperPath: string;
    ready: boolean;
  }): void;
}

type Kind = "text" | "select" | "checkbox" | "password";

interface FieldDef {
  key: keyof Spec;
  label: string;
  kind: Kind;
  hint?: string;
  options?: string[];
  placeholder?: string;
  /** Show this field only when the predicate holds. */
  when?: (spec: Spec) => boolean;
}

interface Section {
  title: string;
  note?: string;
  fields: FieldDef[];
}

const SECTIONS: Section[] = [
  {
    title: "Listener",
    fields: [
      {
        key: "listen",
        label: "Listen address",
        kind: "text",
        placeholder: "127.0.0.1:8080",
        hint: "host:port the server binds. Use 0.0.0.0:8080 to accept connections from other machines.",
      },
      {
        key: "local",
        label: "Local single-user mode",
        kind: "checkbox",
        hint: "Binds to loopback and closes registration after the first account.",
      },
    ],
  },
  {
    title: "Database",
    fields: [
      { key: "dbDriver", label: "Driver", kind: "select", options: ["sqlite", "postgres"] },
      {
        key: "dbDsn",
        label: "DSN / file path",
        kind: "text",
        placeholder: "underflow.db",
        hint: "A file path for sqlite, or a PostgreSQL connection string such as postgres://user:pass@host:5432/underflow?sslmode=disable",
      },
    ],
  },
  {
    title: "Server pepper",
    note:
      "The pepper protects password verifiers. Losing it locks everyone out, and leaking it weakens every account, so back it up somewhere safe.",
    fields: [
      {
        key: "pepper",
        label: "Pepper handling",
        kind: "select",
        options: ["file", "generated"],
        hint: "file reuses the pepper on disk (creating it if absent); generated replaces it with a fresh one.",
      },
      {
        key: "pepperFilePath",
        label: "Pepper file",
        kind: "text",
        placeholder: "<database>.pepper",
        hint: "Leave empty to use the server default: the database path with a .pepper suffix.",
      },
      {
        key: "overwrite",
        label: "Allow replacing an existing pepper",
        kind: "checkbox",
        when: (s) => s.pepper === "generated",
        hint: "Existing accounts cannot log in after a pepper change.",
      },
    ],
  },
  {
    title: "Accounts",
    fields: [
      {
        key: "registration",
        label: "Registration mode",
        kind: "select",
        options: ["open", "closed", "invite"],
        hint: "open: anyone may register. closed: no new accounts. invite: requires the code below.",
      },
      {
        key: "inviteCode",
        label: "Invite code",
        kind: "password",
        when: (s) => s.registration === "invite",
        hint: "Sent by clients as the X-UF-Invite header.",
      },
      {
        key: "argon2Profile",
        label: "Argon2id profile",
        kind: "select",
        options: ["interactive", "moderate", "paranoid"],
        hint: "interactive 64 MiB / moderate 256 MiB / paranoid 1 GiB. Higher is safer and slower.",
      },
      {
        key: "sessionTtl",
        label: "Session lifetime",
        kind: "text",
        placeholder: "12h",
        hint: "Go duration, for example 30m or 12h.",
      },
    ],
  },
  {
    title: "Transport",
    note: "Terminate TLS here for a direct HTTPS listener, or leave empty when a reverse proxy handles it.",
    fields: [
      {
        key: "tlsCert",
        label: "TLS certificate",
        kind: "text",
        placeholder: "/etc/underflow/cert.pem",
      },
      {
        key: "tlsKey",
        label: "TLS key",
        kind: "text",
        placeholder: "/etc/underflow/key.pem",
      },
      {
        key: "trustedProxies",
        label: "Trusted proxies",
        kind: "text",
        placeholder: "127.0.0.1,10.0.0.0/8",
        hint: "Comma-separated addresses allowed to set X-Forwarded-For.",
      },
    ],
  },
  {
    title: "Advanced",
    fields: [
      { key: "logLevel", label: "Log level", kind: "select", options: ["info", "debug"] },
      {
        key: "insecure",
        label: "Insecure mode (no pepper)",
        kind: "checkbox",
        hint: "Generates a throwaway pepper per start. Development only: accounts break on every restart.",
      },
      {
        key: "binary",
        label: "Server binary",
        kind: "text",
        placeholder: "this executable",
        hint: "Leave empty to spawn the binary that runs the launcher.",
      },
    ],
  },
];

const PRESETS: Array<{ name: string; note: string; patch: Partial<Spec> }> = [
  {
    name: "Local development",
    note: "loopback, sqlite, closed registration",
    patch: {
      listen: "127.0.0.1:8080",
      local: true,
      dbDriver: "sqlite",
      dbDsn: "underflow.db",
      pepper: "file",
      registration: "closed",
      argon2Profile: "interactive",
      sessionTtl: "12h",
      logLevel: "info",
      tlsCert: "",
      tlsKey: "",
      trustedProxies: "",
      insecure: false,
    },
  },
  {
    name: "Open sign-up on this machine",
    note: "loopback, open registration",
    patch: { listen: "127.0.0.1:8080", local: false, registration: "open" },
  },
  {
    name: "Share on the LAN",
    note: "all interfaces, no TLS — trusted networks only",
    patch: {
      listen: "0.0.0.0:8080",
      local: false,
      registration: "invite",
      sessionTtl: "8h",
    },
  },
  {
    name: "Behind a reverse proxy",
    note: "loopback bind, closed registration, debug logs",
    patch: {
      listen: "127.0.0.1:8080",
      local: false,
      registration: "closed",
      trustedProxies: "127.0.0.1",
      tlsCert: "",
      tlsKey: "",
    },
  },
];

export function buildForm(initial: Spec): FormHandle {
  const root = el("div", "form");
  const issuesPanel = el("div", "issues");
  issuesPanel.hidden = true;
  root.append(issuesPanel);

  const controls = new Map<keyof Spec, HTMLInputElement | HTMLSelectElement>();
  const rows = new Map<keyof Spec, HTMLElement>();

  root.append(presetBar(controls));

  for (const section of SECTIONS) {
    const card = el("section", "card");
    card.append(el("h2", "", section.title));
    if (section.note) card.append(el("p", "card-note", section.note));
    for (const field of section.fields) {
      const row = el("label", "row");
      const label = el("span", "row-label", field.label);
      row.append(label);
      const control = makeControl(field);
      controls.set(field.key, control);
      row.append(control);
      if (field.hint) row.append(el("span", "row-hint", field.hint));
      const err = el("span", "row-error");
      err.hidden = true;
      row.append(err);
      row.dataset.key = field.key;
      rows.set(field.key, row);
      card.append(row);
    }
    root.append(card);
  }

  const derived = el("section", "card derived");
  derived.append(el("h2", "", "Resolved command"));
  const command = el("code", "command");
  derived.append(command);
  const derivedMeta = el("div", "derived-meta");
  derived.append(derivedMeta);
  root.append(derived);

  function read(): Spec {
    return collect(controls);
  }

  function syncVisibility() {
    const spec = read();
    for (const section of SECTIONS) {
      for (const field of section.fields) {
        if (!field.when) continue;
        const row = rows.get(field.key);
        if (row) row.hidden = !field.when(spec);
      }
    }
  }

  // Keep conditional fields in step with their triggers.
  for (const control of controls.values()) {
    control.addEventListener("change", syncVisibility);
    control.addEventListener("input", syncVisibility);
  }
  syncVisibility();

  function applySpec(spec: Spec) {
    for (const [key, control] of controls) {
      const value = spec[key];
      if (control instanceof HTMLInputElement && control.type === "checkbox") {
        control.checked = Boolean(value);
      } else {
        control.value = value === undefined || value === null ? "" : String(value);
      }
    }
    syncVisibility();
  }

  applySpec(initial);

  return {
    root,
    get: read,
    set: applySpec,
    showIssues(issues) {
      for (const row of rows.values()) {
        row.classList.remove("invalid");
        const err = row.querySelector(".row-error");
        if (err instanceof HTMLElement) {
          err.hidden = true;
          err.textContent = "";
        }
      }
      issuesPanel.replaceChildren();
      const list = issues ?? [];
      issuesPanel.hidden = list.length === 0;
      if (list.length === 0) return;

      issuesPanel.append(el("h3", "", "Configuration problems"));
      const ul = el("ul", "");
      for (const issue of list) {
        const li = el("li", issue.severity);
        li.append(el("strong", "", issue.field), document.createTextNode(" — " + issue.message));
        ul.append(li);
        const row = rows.get(issue.field as keyof Spec);
        if (row) {
          row.classList.add("invalid");
          const err = row.querySelector(".row-error");
          if (err instanceof HTMLElement) {
            err.hidden = false;
            err.textContent = issue.message;
          }
        }
      }
      issuesPanel.append(ul);
    },
    showDerived(info) {
      command.textContent = info.command;
      command.classList.toggle("not-ready", !info.ready);
      derivedMeta.replaceChildren();
      const link = document.createElement("a");
      link.href = info.url;
      link.target = "_blank";
      link.rel = "noreferrer noopener";
      link.textContent = info.url;
      derivedMeta.append(metaItem("App URL", link));
      derivedMeta.append(
        metaItem("Health probe", document.createTextNode(info.probeUrl || "not available for port 0")),
      );
      derivedMeta.append(
        metaItem("Pepper file", document.createTextNode(info.pepperPath || "not set")),
      );
    },
  };
}

function metaItem(label: string, value: Node): HTMLElement {
  const wrap = el("div", "meta-item");
  wrap.append(el("span", "meta-label", label), value);
  return wrap;
}

function presetBar(controls: Map<keyof Spec, HTMLInputElement | HTMLSelectElement>): HTMLElement {
  const bar = el("section", "card presets");
  bar.append(el("h2", "", "Presets"));
  const row = el("div", "preset-row");
  for (const preset of PRESETS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "preset";
    btn.append(el("span", "preset-name", preset.name), el("span", "preset-note", preset.note));
    btn.addEventListener("click", () => {
      for (const [key, value] of Object.entries(preset.patch)) {
        const control = controls.get(key as keyof Spec);
        if (!control) continue;
        if (control instanceof HTMLInputElement && control.type === "checkbox") {
          control.checked = Boolean(value);
        } else {
          control.value = String(value);
        }
        control.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
    row.append(btn);
  }
  bar.append(row);
  return bar;
}

function makeControl(field: FieldDef): HTMLInputElement | HTMLSelectElement {
  if (field.kind === "select") {
    const select = document.createElement("select");
    for (const option of field.options ?? []) {
      const o = document.createElement("option");
      o.value = option;
      o.textContent = option;
      select.append(o);
    }
    return select;
  }
  const input = document.createElement("input");
  input.type = field.kind === "checkbox" ? "checkbox" : field.kind === "password" ? "password" : "text";
  if (field.placeholder) input.placeholder = field.placeholder;
  if (field.kind === "text" || field.kind === "password") input.spellcheck = false;
  return input;
}

function collect(controls: Map<keyof Spec, HTMLInputElement | HTMLSelectElement>): Spec {
  const value = (key: keyof Spec): string | boolean => {
    const control = controls.get(key);
    if (!control) return "";
    if (control instanceof HTMLInputElement && control.type === "checkbox") return control.checked;
    return control.value.trim();
  };
  return {
    listen: String(value("listen")),
    local: Boolean(value("local")),
    dbDriver: String(value("dbDriver")),
    dbDsn: String(value("dbDsn")),
    pepper: String(value("pepper")),
    overwrite: Boolean(value("overwrite")),
    pepperFilePath: String(value("pepperFilePath")),
    registration: String(value("registration")),
    inviteCode: String(value("inviteCode")),
    argon2Profile: String(value("argon2Profile")),
    sessionTtl: String(value("sessionTtl")),
    logLevel: String(value("logLevel")),
    trustedProxies: String(value("trustedProxies")),
    tlsCert: String(value("tlsCert")),
    tlsKey: String(value("tlsKey")),
    insecure: Boolean(value("insecure")),
    binary: String(value("binary")),
  };
}

function el(tag: string, className: string, text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
