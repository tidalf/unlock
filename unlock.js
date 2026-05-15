// rustofill biometric unlock page. Runs on https://tidalf.github.io/rustofill/
// (or wherever you host it). The extension opens this page in a new window;
// the bio-bridge content script on this origin relays messages between the
// page and the extension service worker.
//
// Two actions:
//   action=enroll  → page receives an IKM from the extension, creates a
//                    platform passkey with the PRF extension, wraps the IKM
//                    under PRF(salt), returns {credentialId, prfSalt,
//                    wrappedIkm, wrapIv} to the extension.
//   action=unlock  → page receives the envelope from the extension, asks
//                    WebAuthn to assert the credential and evaluate PRF on
//                    the stored salt, unwraps the IKM under PRF(salt),
//                    returns {ikm} to the extension.
//
// All transport between page ↔ extension is via window.postMessage to the
// same origin (the bridge content script listens on this window). The IKM
// is never sent in a URL or persisted on this page.

const msgEl = document.getElementById("msg");
const statusEl = document.getElementById("status");

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = "status" + (kind ? " " + kind : "");
}

function b64urlEncode(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function post(payload) {
  window.postMessage({ source: "rustofill-bio", ...payload }, location.origin);
}

async function doEnroll(ikmB64u) {
  setStatus("creating a platform credential — confirm with biometric…");
  const ikm = b64urlDecode(ikmB64u);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: "rustofill", id: location.hostname },
      user: { id: userId, name: "rustofill", displayName: "rustofill biometric" },
      challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "preferred",
        userVerification: "required",
      },
      extensions: { prf: {} },
      timeout: 60000,
    },
  });
  if (!cred) throw new Error("credential creation cancelled");

  // The PRF extension is only evaluated reliably on the GET ceremony (some
  // platforms don't return prf results from create()). Generate a fresh salt
  // and ask the authenticator for prf evaluation in a follow-up assertion.
  setStatus("deriving wrapping key from biometric — confirm again if asked…");
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: "public-key", id: cred.rawId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSalt } } },
      timeout: 60000,
    },
  });
  const prfResults = assertion.getClientExtensionResults().prf;
  const prfFirst = prfResults && prfResults.results && prfResults.results.first;
  if (!prfFirst) {
    throw new Error(
      "this device or browser doesn't support the WebAuthn PRF extension",
    );
  }

  const aesKey = await crypto.subtle.importKey(
    "raw",
    prfFirst,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedIkm = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: wrapIv }, aesKey, ikm),
  );

  setStatus("biometric enrolled — sending wrapped key to extension…", "ok");
  post({
    kind: "enrolled",
    credentialId: b64urlEncode(cred.rawId),
    prfSalt: b64urlEncode(prfSalt),
    wrappedIkm: b64urlEncode(wrappedIkm),
    wrapIv: b64urlEncode(wrapIv),
  });

  msgEl.textContent = "All done. You can close this window.";
  // Auto-close after a beat (Chrome only allows close() on extension-opened tabs).
  setTimeout(() => { try { window.close(); } catch {} }, 1200);
}

async function doUnlock(envelope) {
  setStatus("asserting platform credential — confirm with biometric…");
  const credentialId = b64urlDecode(envelope.credentialId);
  const prfSalt = b64urlDecode(envelope.prfSalt);
  const wrappedIkm = b64urlDecode(envelope.wrappedIkm);
  const wrapIv = b64urlDecode(envelope.wrapIv);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSalt } } },
      timeout: 60000,
    },
  });
  const prfResults = assertion.getClientExtensionResults().prf;
  const prfFirst = prfResults && prfResults.results && prfResults.results.first;
  if (!prfFirst) {
    throw new Error("PRF evaluation failed — this device may not support it");
  }

  const aesKey = await crypto.subtle.importKey(
    "raw",
    prfFirst,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const ikm = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: wrapIv }, aesKey, wrappedIkm),
  );

  setStatus("unwrapped vault key — handing back to extension…", "ok");
  post({ kind: "unlocked", ikm: b64urlEncode(ikm) });
  msgEl.textContent = "All done. You can close this window.";
  setTimeout(() => { try { window.close(); } catch {} }, 1200);
}

window.addEventListener("message", async (event) => {
  if (event.source !== window) return;
  if (event.data?.source !== "rustofill-ext") return;
  const { action } = event.data;
  try {
    if (action === "enroll") {
      msgEl.textContent = "Enabling biometric unlock…";
      await doEnroll(event.data.ikm);
    } else if (action === "unlock") {
      msgEl.textContent = "Unlocking your vault…";
      await doUnlock(event.data.envelope);
    } else {
      throw new Error("unknown action: " + action);
    }
  } catch (e) {
    setStatus("error: " + (e && e.message ? e.message : String(e)), "err");
    post({ kind: "error", error: String(e && e.message ? e.message : e) });
  }
});

// Tell the bridge we're ready to receive the action+payload.
post({ kind: "ready" });
