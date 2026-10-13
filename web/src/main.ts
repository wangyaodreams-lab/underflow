// Underflow web client: a small, framework-free UI over the WASM crypto core.
import { App } from "./app";
import { emptyItem, type DecryptedItem, type Item } from "./types";

const app = new App();
const root = document.getElementById("app")!;

const ui = {
  mode: "unlock" as "unlock" | "register",
  selected: null as string | null,
  editing: false,
  draft: null as Item | null,
  search: "",
};

type Child = Node | string;

function h(tag: string, attrs: Record<string, unknown> = {}, ...children: Child[]): HTMLElement {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = String(v);
    else if (k.startsWith("on") && typeof v === "function") {
      e.addEventListener(k.slice(2), v as EventListener);
    } else if (v !== undefined && v !== null && v !== false) {
      e.setAttribute(k, String(v));
    }
  }
  for (const c of children) e.append(c);
  return e;
}

let toastTimer: number | undefined;
function toast(msg: string): void {
  let el = document.getElementById("toast");
  if (!el) {
    el = h("div", { id: "toast", class: "toast" });
    document.body.append(el);
  }
  el.textContent = msg;
  el.classList.add("show");
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => el!.classList.remove("show"), 2000);
}

async function copy(text: string, label: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} copied (clears in 30s)`);
    window.setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => undefined);
    }, 30_000);
  } catch {
    toast("clipboard unavailable");
  }
}

function brand(): HTMLElement {
  return h("div", { class: "brand" }, h("span", { class: "logo" }, "U"), "Underflow");
}

function errorBox(): HTMLElement {
  return h("div", { class: "error", id: "err" });
}

function showError(msg: string): void {
  const el = document.getElementById("err");
  if (el) el.textContent = msg;
}

// --- lock / auth screen ---

function renderLock(): void {
  ui.selected = null;
  ui.editing = false;
  root.replaceChildren();

  const email = h("input", { id: "email", type: "email", autocomplete: "username", value: app.email }) as HTMLInputElement;
  const password = h("input", { id: "password", type: "password", autocomplete: "current-password" }) as HTMLInputElement;
  const confirm = h("input", { id: "confirm", type: "password", autocomplete: "new-password" }) as HTMLInputElement;
  const confirmRow = h("label", {}, "Confirm password", confirm);
  confirmRow.style.display = ui.mode === "register" ? "" : "none";

  const submit = h("button", { class: "primary", type: "submit" }, ui.mode === "register" ? "Create account" : "Unlock");
  const toggle = h(
    "button",
    {
      type: "button",
      class: "link",
      onclick: () => {
        ui.mode = ui.mode === "register" ? "unlock" : "register";
        renderLock();
      },
    },
    ui.mode === "register" ? "Already have an account? Unlock" : "No account? Create one",
  );

  const form = h(
    "form",
    {
      onsubmit: async (ev: Event) => {
        ev.preventDefault();
        showError("");
        submit.setAttribute("disabled", "true");
        try {
          const e = email.value.trim();
          if (!e || !password.value) throw new Error("email and password are required");
          if (ui.mode === "register") {
            if (password.value.length < 12) throw new Error("master password must be at least 12 characters");
            if (password.value !== confirm.value) throw new Error("passwords do not match");
            await app.register(e, password.value);
          } else {
            await app.login(e, password.value);
          }
          password.value = "";
          renderVault();
        } catch (err) {
          showError(err instanceof Error ? err.message : String(err));
        } finally {
          submit.removeAttribute("disabled");
        }
      },
    },
    h("label", {}, "Email", email),
    h("label", {}, "Master password", password),
    confirmRow,
    submit,
    toggle,
    errorBox(),
  );

  root.append(
    h(
      "div",
      { class: "lock" },
      brand(),
      h("p", { class: "muted" }, "Your master password never leaves this device."),
      form,
      h("p", { class: "hint" }, "Unlocking derives your keys locally with Argon2id; the server only ever sees ciphertext."),
    ),
  );
  email.focus();
}

// --- vault screen ---

function renderVault(): void {
  root.replaceChildren();

  const search = h("input", {
    class: "search",
    placeholder: "Search",
    value: ui.search,
    oninput: (ev: Event) => {
      ui.search = (ev.target as HTMLInputElement).value;
      renderList();
    },
  }) as HTMLInputElement;

  const newBtn = h("button", { class: "primary", onclick: newItem }, "New item");
  const lockBtn = h("button", { onclick: () => app.lock() }, "Lock");
  const logoutBtn = h(
    "button",
    {
      onclick: async () => {
        await app.logout();
        renderLock();
      },
    },
    "Log out",
  );

  const autoLock = h(
    "select",
    {
      onchange: (ev: Event) => {
        const v = Number((ev.target as HTMLSelectElement).value);
        app.setAutoLock(v);
        localStorage.setItem("uf.autoLock", String(v));
        toast(`Auto-lock: ${v} min`);
      },
    },
    ...[1, 5, 10, 30, 60].map((m) =>
      h("option", { value: m, selected: m === app.autoLockMinutes }, `${m} min`),
    ),
  ) as HTMLSelectElement;

  const header = h(
    "header",
    {},
    brand(),
    h("div", { class: "spacer" }),
    h("span", { class: "muted" }, app.email),
    h("label", { class: "autolock" }, "Auto-lock", autoLock),
    newBtn,
    lockBtn,
    logoutBtn,
  );

  const list = h("div", { class: "list", id: "list" });
  const detail = h("div", { class: "detail", id: "detail" });
  const body = h("div", { class: "body" }, h("aside", {}, search, list), detail);
  root.append(h("div", { class: "vault" }, header, body));
  renderList();
  renderDetail();
}

function filtered(): DecryptedItem[] {
  const q = ui.search.trim().toLowerCase();
  const items = [...app.items].sort((a, b) => a.item.name.localeCompare(b.item.name));
  if (!q) return items;
  return items.filter((d) => {
    const it = d.item;
    return (
      it.name.toLowerCase().includes(q) ||
      (it.username ?? "").toLowerCase().includes(q) ||
      (it.urls ?? []).some((u) => u.toLowerCase().includes(q))
    );
  });
}

function renderList(): void {
  const list = document.getElementById("list");
  if (!list) return;
  list.replaceChildren();
  const items = filtered();
  if (items.length === 0) {
    list.append(h("div", { class: "muted pad" }, app.items.length === 0 ? "No items yet." : "No matches."));
    return;
  }
  for (const d of items) {
    const isSel = d.item.id === ui.selected;
    list.append(
      h(
        "button",
        {
          class: `row${isSel ? " selected" : ""}`,
          onclick: () => {
            ui.selected = d.item.id;
            ui.editing = false;
            ui.draft = null;
            renderList();
            renderDetail();
          },
        },
        h("div", { class: "row-name" }, d.item.name || "(untitled)"),
        h("div", { class: "row-sub muted" }, d.item.username || d.item.urls?.[0] || d.item.type),
      ),
    );
  }
}

function selectedItem(): DecryptedItem | null {
  return app.items.find((d) => d.item.id === ui.selected) ?? null;
}

function newItem(): void {
  const draft = emptyItem(crypto.randomUUID());
  ui.selected = draft.id;
  ui.draft = draft;
  ui.editing = true;
  renderList();
  renderDetail();
}

function renderDetail(): void {
  const detail = document.getElementById("detail");
  if (!detail) return;
  detail.replaceChildren();

  if (ui.editing && ui.draft) {
    detail.append(renderEditor(ui.draft));
    return;
  }
  const di = selectedItem();
  if (!di) {
    detail.append(h("div", { class: "muted pad" }, "Select an item or create a new one."));
    return;
  }
  const it = di.item;

  const field = (label: string, value: string, secret = false, label2 = label) =>
    h(
      "div",
      { class: "field" },
      h("div", { class: "field-label muted" }, label),
      h("div", { class: "field-value" }, secret ? "••••••••" : value || "—"),
      value ? h("button", { class: "copy", onclick: () => copy(value, label2) }, "Copy") : "",
    );

  detail.append(
    h("h2", {}, it.name || "(untitled)"),
    field("Username", it.username ?? ""),
    field("Password", it.password ?? "", true, "Password"),
    field("URL", it.urls?.[0] ?? "", false, "URL"),
    it.notes ? h("div", { class: "field" }, h("div", { class: "field-label muted" }, "Notes"), h("div", { class: "field-value pre" }, it.notes)) : "",
    h(
      "div",
      { class: "actions" },
      h(
        "button",
        {
          class: "primary",
          onclick: () => {
            ui.draft = JSON.parse(JSON.stringify(it)) as Item;
            ui.editing = true;
            renderDetail();
          },
        },
        "Edit",
      ),
      h(
        "button",
        {
          class: "danger",
          onclick: async () => {
            if (!confirm(`Delete "${it.name}"?`)) return;
            await app.deleteItem(it.id);
            ui.selected = null;
            renderList();
            renderDetail();
          },
        },
        "Delete",
      ),
    ),
  );
}

function renderEditor(draft: Item): HTMLElement {
  const name = h("input", { value: draft.name, placeholder: "Name" }) as HTMLInputElement;
  const username = h("input", { value: draft.username ?? "", placeholder: "Username" }) as HTMLInputElement;
  const password = h("input", { value: draft.password ?? "", placeholder: "Password" }) as HTMLInputElement;
  const url = h("input", { value: draft.urls?.[0] ?? "", placeholder: "https://" }) as HTMLInputElement;
  const notes = h("textarea", { rows: 4 }, draft.notes ?? "") as HTMLTextAreaElement;

  const gen = h(
    "button",
    {
      type: "button",
      onclick: () => {
        password.value = app.generatePassword(20);
      },
    },
    "Generate",
  );
  const show = h(
    "button",
    {
      type: "button",
      onclick: () => {
        password.type = password.type === "password" ? "text" : "password";
      },
    },
    "Show",
  );

  const save = h(
    "button",
    {
      class: "primary",
      onclick: async () => {
        try {
          const next: Item = {
            ...draft,
            name: name.value.trim(),
            username: username.value.trim(),
            password: password.value,
            urls: url.value ? [url.value.trim()] : [],
            notes: notes.value,
          };
          if (!next.name) throw new Error("name is required");
          await app.saveItem(next);
          ui.editing = false;
          ui.draft = null;
          renderList();
          renderDetail();
          toast("Saved");
        } catch (err) {
          toast(err instanceof Error ? err.message : String(err));
        }
      },
    },
    "Save",
  );
  const cancel = h(
    "button",
    {
      onclick: () => {
        ui.editing = false;
        ui.draft = null;
        if (app.items.find((d) => d.item.id === ui.selected) === undefined) ui.selected = null;
        renderList();
        renderDetail();
      },
    },
    "Cancel",
  );

  return h(
    "form",
    {
      class: "editor",
      onsubmit: (ev: Event) => {
        ev.preventDefault();
        (save as HTMLButtonElement).click();
      },
    },
    h("label", {}, "Name", name),
    h("label", {}, "Username", username),
    h("label", {}, "Password", h("div", { class: "row-inline" }, password, gen, show)),
    h("label", {}, "URL", url),
    h("label", {}, "Notes", notes),
    h("div", { class: "actions" }, save, cancel),
  );
}

async function boot(): Promise<void> {
  root.replaceChildren(h("div", { class: "loading" }, "Loading Underflow…"));
  const saved = Number(localStorage.getItem("uf.autoLock"));
  if (saved > 0) app.autoLockMinutes = saved;
  try {
    await app.init();
  } catch (err) {
    root.replaceChildren(h("div", { class: "lock" }, brand(), h("div", { class: "error" }, "Failed to load: " + (err instanceof Error ? err.message : String(err)))));
    return;
  }
  app.onLock = () => renderLock();
  renderLock();
}

void boot();
