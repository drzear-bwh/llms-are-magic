// Password gate for the locked build (scripts/build_locked.mjs).
// site.bin = salt (16 bytes) + IV (12) + AES-GCM ciphertext of a JSON map
// {path: text} holding the app shell, the scripts and the data. The key is
// PBKDF2-SHA-256 of the password (trimmed, lower case). Once a password works,
// the raw key is kept on this phone so a reload doesn't ask again.
const ITER = 600000, SAVED = "hq-key";
const $ = (id) => document.getElementById(id);
const toB64 = (u8) => btoa(String.fromCharCode(...u8));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let bin = null;
const load = () => (bin ??= fetch("site.bin").then((r) => {
  if (!r.ok) throw new Error(`site.bin: ${r.status}`);
  return r.arrayBuffer();
}).catch((e) => { bin = null; throw e; }));

async function derive(pw) {
  const salt = new Uint8Array(await load(), 0, 16);
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw.trim().normalize("NFC").toLowerCase()), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITER }, base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
}

async function open(key) {
  const buf = await load();
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(buf, 16, 12) }, key, new Uint8Array(buf, 28));
  return JSON.parse(new TextDecoder().decode(plain));
}

// Swap the gate for the app and run its modules from blob URLs. Each module's
// imports ("./x.js") are rewritten to the blob URL of x, dependencies first.
function start(files) {
  globalThis.__LAM_FILES = files;
  document.body.innerHTML = files["shell.html"];
  const urls = {};
  const load = (name) => {
    if (urls[name]) return urls[name];
    const src = files[`js/${name}`];
    if (src == null) throw new Error(`missing module js/${name}`);
    const code = src.replace(/from "\.\/([a-z0-9]+\.js)"/g, (_, dep) => `from "${load(dep)}"`);
    return (urls[name] = URL.createObjectURL(new Blob([code], { type: "text/javascript" })));
  };
  return import(load("app.js"));
}

const wrong = (e) => e?.name === "OperationError";

$("gateForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("gateBtn"), msg = $("gateMsg");
  btn.disabled = true;
  msg.textContent = "Looking up your booking…";
  try {
    const key = await derive($("pw").value);
    const files = await open(key);
    try { localStorage.setItem(SAVED, toB64(new Uint8Array(await crypto.subtle.exportKey("raw", key)))); } catch { /* private mode */ }
    await start(files);
  } catch (err) {
    msg.textContent = wrong(err) ? "Error 404: booking not found. Try again." : "The hotel didn't load. Check your connection and try again.";
    btn.disabled = false;
  }
});

(async () => {
  let saved = null;
  try { saved = localStorage.getItem(SAVED); } catch { /* private mode */ }
  if (saved) {
    try {
      return await start(await open(await crypto.subtle.importKey("raw", fromB64(saved), "AES-GCM", true, ["decrypt"])));
    } catch (err) {
      if (wrong(err)) try { localStorage.removeItem(SAVED); } catch { /* ignore */ }
    }
  }
  $("gate").hidden = false;
})();
