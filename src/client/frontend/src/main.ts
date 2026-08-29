import "./style.css";
import pigeonIcon from "../../../../resources/pigeon.svg";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import { api } from "./api";
import type { Account } from "./types";
import { esc, stamp } from "./format";
import { chatList as chatListView } from "./chats";

let account: Account;
let selected = "";
let page: "chats" | "contacts" | "devices" | "settings" = "chats";
let notice = "";
let setupServer = "";
let contactDraft = "";
let relayDraft = "";
const messageDrafts = new Map<string, string>();
const app = document.querySelector<HTMLDivElement>("#app")!;
type EditorSnapshot = { key: string; draftKey?: string; selectionStart: number | null; selectionEnd: number | null };
const flash = (message: string) => { notice = message; render(); window.setTimeout(() => { notice = ""; render(); }, 3500); };
async function refresh() { account = await api.status(); render(); }
async function openConversation(id: string) { selected = id; page = "chats"; await api.markRead(id); await refresh(); }
function captureEditor(): EditorSnapshot | undefined {
  const editor = document.activeElement;
  if (!(editor instanceof HTMLInputElement || editor instanceof HTMLTextAreaElement)) return undefined;
  const key = editor.form?.id === "setup" ? "setup"
    : editor.id === "contact-card" ? "contact"
    : editor.id === "relay-address" ? "relay"
    : editor.form?.id === "composer" ? "message"
    : undefined;
  if (!key) return undefined;
  const draftKey = key === "message" ? `${account.selected_account ?? ""}:${selected}` : undefined;
  if (key === "setup") setupServer = editor.value;
  if (key === "contact") contactDraft = editor.value;
  if (key === "relay") relayDraft = editor.value;
  if (key === "message" && draftKey) messageDrafts.set(draftKey, editor.value);
  return { key, draftKey, selectionStart: editor.selectionStart, selectionEnd: editor.selectionEnd };
}
function restoreEditor(snapshot?: EditorSnapshot) {
  if (!snapshot) return;
  const selector = snapshot.key === "setup" ? "#setup input"
    : snapshot.key === "contact" ? "#contact-card"
    : snapshot.key === "relay" ? "#relay-address"
    : "#composer textarea";
  const editor = app.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector);
  if (!editor || editor.disabled) return;
  editor.focus({ preventScroll: true });
  if (snapshot.selectionStart !== null && snapshot.selectionEnd !== null) {
    editor.setSelectionRange(snapshot.selectionStart, snapshot.selectionEnd);
  }
}
function chatList() { return chatListView(account.conversations, selected); }
function contactsPage() { return `<section class="panel contacts-panel"><header class="panel-heading"><div><p class="eyebrow">PEOPLE</p><h1>Contacts</h1><p>Paste a signed contact card. Pigeon verifies it in Rust before saving it.</p></div><button class="secondary" id="share-card">Copy my card</button></header><form id="import-contact" class="contact-form"><label for="contact-card">Contact card</label><textarea required id="contact-card" name="card" placeholder="Paste a Pigeon contact card" aria-describedby="contact-help">${esc(contactDraft)}</textarea><small id="contact-help">Your paste remains here until Pigeon confirms the contact was added.</small><div><button type="submit">Add contact</button><button type="button" class="secondary" id="clear-contact" ${contactDraft ? "" : "disabled"}>Clear</button></div></form><div class="rows contact-rows">${account.contacts.map(c => `<div><span class="avatar">${c.id.slice(0,2)}</span><span><b>${c.id.slice(0, 16)}</b><small>${esc(c.server)}</small></span></div>`).join("") || "<p class=empty>No contacts yet. Add a verified contact card to start a chat.</p>"}</div></section>`; }
function devicesPage() { const rows = account.devices.map(d => `<div><span class="device-state ${d.state}"></span><span><b>${d.id.slice(0, 20)}</b><small>${d.state}${d.last_activity ? ` · ${stamp(d.last_activity)}` : " · activity not yet reported by relay"}</small></span></div>`).join("") || "<p class=empty>No device roster available.</p>"; return `<section class="panel"><h1>Devices & account</h1><p>Device authorization is signed by your root identity.</p><div class="rows">${rows}</div></section>`; }
function settingsPage() { const r = account.route; if (!relayDraft) relayDraft = r?.server ?? account.server ?? ""; return `<section class="panel"><h1>Settings</h1><h2>Accounts</h2><div class="rows">${account.accounts.map(a => `<button data-switch-account="${a.id}" ${a.id === account.selected_account ? "disabled" : ""}><b>${esc(a.label)}</b><small>${a.identity.slice(0, 16)}${a.id === account.selected_account ? " · current" : ""}</small></button>`).join("")}</div><p><button id="settings-create-account">Create account</button> <button id="settings-import-account" class="secondary">Import backup</button></p><h2>Relay</h2><p>Changing relay creates a newer signed routing record for this account only.</p><form id="relay-form" class="contact-form"><label for="relay-address">Relay address</label><input required id="relay-address" name="server" value="${esc(relayDraft)}" placeholder="127.0.0.1:8443"><div><button type="submit">Change relay</button></div></form><div class="rows"><div><b>Current relay</b><small>${esc(r?.server ?? account.server ?? "Unavailable")}</small></div><div><b>Routing revision</b><small>${r?.revision ?? "Unavailable"}</small></div><div><b>Relay identity fingerprint</b><small class="fingerprint">${r?.relay_fingerprint ?? "Unavailable"}</small></div><div><b>TLS SPKI pin</b><small class="fingerprint">${r?.tls_spki_fingerprint ?? "Unavailable"}</small></div></div></section>`; }
function render() {
  const editorSnapshot = captureEditor();
  queueMicrotask(() => restoreEditor(editorSnapshot));
  if (!account.state_exists) { app.innerHTML = `<main class="setup"><img src="${pigeonIcon}" alt="Pigeon"><section><p class="eyebrow">WELCOME TO PIGEON</p><h1>Your Pigeon accounts</h1><p>Create a new cryptographic identity, import a secure backup, or choose an account stored on this device.</p>${notice ? `<p class="setup-error" role="alert">${esc(notice)}</p>` : ""}<div class="rows">${account.accounts.map(a => `<button data-account="${a.id}">${esc(a.label)}<small>${a.identity.slice(0,16)}</small></button>`).join("")}</div><button id="create-account">Create new account</button><button id="import-account" class="secondary">Import identity backup</button></section></main>`; document.querySelector<HTMLButtonElement>("#create-account")!.onclick = async () => { try { await api.createAccount(); await refresh(); } catch (error) { notice=String(error); render(); } }; document.querySelector<HTMLButtonElement>("#import-account")!.onclick = async () => { try { const backup = await open({ multiple: false, directory: false, filters: [{ name: "Pigeon identity backup", extensions: ["json"] }] }); if (backup === null) return; if (typeof backup !== "string") throw new Error("The selected backup does not provide a local file path."); await api.importAccount(backup); notice="Identity backup imported."; await refresh(); } catch (error) { notice=`Import failed: ${String(error)}`; render(); } }; document.querySelectorAll<HTMLButtonElement>("[data-account]").forEach(button => button.onclick=async()=>{ try { await api.selectAccount(button.dataset.account!); await refresh(); } catch (error) { notice=String(error); render(); } }); return; }
  if (account.needs_relay) { app.innerHTML = `<main class="setup"><img src="${pigeonIcon}" alt="Pigeon"><section><p class="eyebrow">ACCOUNT SETUP</p><h1>Choose a relay</h1>${notice ? `<p class="setup-error" role="alert">${esc(notice)}</p>` : ""}<form id="setup"><label>Relay address<input required name="server" value="${esc(setupServer)}" placeholder="127.0.0.1:8443"></label><button>Next</button></form></section></main>`; const setupForm = document.querySelector<HTMLFormElement>("#setup")!; const serverInput = setupForm.elements.namedItem("server") as HTMLInputElement; serverInput.oninput=()=>{setupServer=serverInput.value}; setupForm.onsubmit=async event=>{event.preventDefault();setupServer=serverInput.value.trim();try{await api.configureRelay(setupServer);await refresh()}catch(error){notice=String(error);render()}}; return; }
  const active = account.conversations.find(c => c.id === selected);
  const messages = account.messages.filter(m => m.conversation === selected).map(m => `<article class="message ${m.sender === account.identity ? "outgoing" : ""}"><p>${esc(m.text)}</p><small>${stamp(m.timestamp)}</small></article>`).join("") || `<div class="notice">Messages are encrypted before they leave your device.</div>`;
  const draftKey = `${account.selected_account ?? ""}:${selected}`;
  const body = page === "contacts" ? contactsPage() : page === "devices" ? devicesPage() : page === "settings" ? settingsPage() : `<section id="messages">${messages}</section><form id="composer" class="composer"><textarea name="text" placeholder="Message" ${selected ? "" : "disabled"}>${esc(messageDrafts.get(draftKey) ?? "")}</textarea><button ${selected ? "" : "disabled"}>Send</button></form>`;
  app.innerHTML = `<div class="shell"><aside><header><img src="${pigeonIcon}" alt=""><div><b>Pigeon</b><small>${account.identity?.slice(0, 16) ?? ""}</small></div></header><nav>${(["chats", "contacts", "devices", "settings"] as const).map(item => `<button data-page="${item}" class="${page === item ? "selected" : ""}">${item === "chats" ? "Chats" : item[0].toUpperCase() + item.slice(1)}</button>`).join("")}</nav><div class="list">${page === "chats" ? chatList() : ""}</div><footer><span class="status"></span>Connected to ${esc(account.server ?? "")}</footer></aside><main class="chat"><header><button class="back">‹</button><div><b>${page === "chats" ? (active?.title ?? "Select a conversation") : page[0].toUpperCase() + page.slice(1)}</b><small>${page === "chats" ? (active ? "End-to-end encrypted" : "Choose a chat to begin") : "Account-local state"}</small></div></header>${notice ? `<p class="toast">${esc(notice)}</p>` : ""}${body}</main></div>`;
  document.querySelectorAll<HTMLButtonElement>("[data-page]").forEach(button => button.onclick = () => { page = button.dataset.page as typeof page; render(); });
  document.querySelectorAll<HTMLButtonElement>("[data-switch-account]").forEach(button => button.onclick = async () => { try { await api.selectAccount(button.dataset.switchAccount!); selected = ""; relayDraft = ""; notice = ""; await refresh(); } catch (error) { flash(`Could not switch account: ${String(error)}`); } });
  document.querySelector<HTMLButtonElement>("#settings-create-account")?.addEventListener("click", async () => { try { await api.createAccount(); selected = ""; page = "settings"; await refresh(); } catch (error) { flash(`Could not create account: ${String(error)}`); } });
  document.querySelector<HTMLButtonElement>("#settings-import-account")?.addEventListener("click", async () => { try { const backup = await open({ multiple: false, directory: false, filters: [{ name: "Pigeon identity backup", extensions: ["json"] }] }); if (typeof backup !== "string") return; await api.importAccount(backup); selected = ""; page = "settings"; await refresh(); flash("Identity backup imported."); } catch (error) { flash(`Import failed: ${String(error)}`); } });
  const relayForm = document.querySelector<HTMLFormElement>("#relay-form");
  const relayInput = relayForm?.elements.namedItem("server") as HTMLInputElement | undefined;
  if (relayInput) relayInput.oninput = () => { relayDraft = relayInput.value; };
  relayForm?.addEventListener("submit", async event => { event.preventDefault(); relayDraft = relayInput!.value.trim(); try { await api.migrateRelay(relayDraft); await refresh(); flash("Relay routing updated."); } catch (error) { flash(`Could not change relay: ${String(error)}`); } });
  document.querySelectorAll<HTMLButtonElement>("[data-conversation]").forEach(button => button.onclick = () => void openConversation(button.dataset.conversation!));
  const composer = document.querySelector<HTMLFormElement>("#composer");
  const messageInput = composer?.elements.namedItem("text") as HTMLTextAreaElement | undefined;
  if (messageInput) messageInput.oninput = () => { messageDrafts.set(draftKey, messageInput.value); };
  composer?.addEventListener("submit", async event => { event.preventDefault(); const text = messageDrafts.get(draftKey) ?? ""; if (!text.trim() || !selected) return; try { selected.startsWith("group:") ? await api.groupSend(selected.slice(6), text) : await api.send(selected, text); messageDrafts.delete(draftKey); await refresh(); } catch (error) { flash(String(error)); } });
  const contactForm = document.querySelector<HTMLFormElement>("#import-contact");
  const contactInput = contactForm?.elements.namedItem("card") as HTMLTextAreaElement | undefined;
  if (contactInput) contactInput.oninput = () => { contactDraft = contactInput.value; };
  contactForm?.addEventListener("submit", async event => { event.preventDefault(); try { await api.importContact(contactDraft.trim()); contactDraft = ""; await refresh(); flash("Contact verified and added."); } catch (error) { flash(`Could not add contact: ${String(error)}`); } });
  document.querySelector<HTMLButtonElement>("#clear-contact")?.addEventListener("click", () => { contactDraft = ""; render(); });
  document.querySelector<HTMLButtonElement>("#share-card")?.addEventListener("click", async () => { try { await navigator.clipboard.writeText(await api.shareCard()); flash("Signed contact card copied."); } catch (error) { flash(`Could not copy card: ${String(error)}`); } });
}
refresh().catch(error => { app.innerHTML = `<main class="error">Unable to load Pigeon: ${esc(String(error))}</main>`; });
void listen<Account>("pigeon://state", event => { account = event.payload; render(); });
void listen<string>("pigeon://sync-error", event => flash(`Background sync failed: ${event.payload}`));
