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

async function doEnroll(ikmB64u, _mode) {
  // One enroll ceremony for everything — Touch ID, Hello, YubiKey, phone.
  //
  // userVerification: "preferred" surfaces Touch ID (which UV=discouraged
  // would have filtered out on macOS Chrome) while still letting a
  // YubiKey 5.4+ without PIN stay single-tap — the authenticator can't
  // do UV without PIN so it falls back to UP-only and CTAP 2.1 uses
  // CredRandomWithoutUV. PRF derivation stays consistent across enroll
  // and unlock.
  //
  // No authenticatorAttachment hint: lets the user pick any device the
  // browser offers (platform or roaming or hybrid-via-QR). The earlier
  // split between "security-key" and "platform" was misleading because
  // "cross-platform" in WebAuthn still includes hybrid/phone — so the
  // chooser looked identical in both branches anyway.
  setStatus("creating a credential — confirm with biometric, Touch ID, or tap your security key…");
  const ikm = b64urlDecode(ikmB64u);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));

  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: "rustofill", id: location.hostname },
      user: { id: userId, name: "rustofill", displayName: "rustofill vault" },
      challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: {
        residentKey: "discouraged",
        userVerification: "preferred",
      },
      // Eval PRF on create — modern stacks return the result in
      // getClientExtensionResults() so we don't need a follow-up get().
      extensions: { prf: { eval: { first: prfSalt } } },
      timeout: 60000,
    },
  });
  if (!cred) throw new Error("credential creation cancelled");

  // Try prf-on-create first. If the authenticator/browser didn't return a
  // PRF result there, fall back to a follow-up get() (older stacks).
  let prfFirst;
  const createPrf = cred.getClientExtensionResults().prf;
  if (createPrf && createPrf.results && createPrf.results.first) {
    prfFirst = createPrf.results.first;
  } else {
    setStatus("deriving wrapping key — confirm again…");
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: cred.rawId }],
        userVerification: "preferred",
        extensions: { prf: { eval: { first: prfSalt } } },
        timeout: 60000,
      },
    });
    const r = assertion.getClientExtensionResults().prf;
    prfFirst = r && r.results && r.results.first;
  }
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

  setStatus("authenticator enrolled — sending wrapped key to extension…", "ok");
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

async function doUnlock(payload) {
  // v2 sent a single { envelope }; v3 sends { envelopes: [...] } so the
  // user can pick any enrolled authenticator. Accept both for forward
  // compat with older extensions, and prefer the list when present.
  const envelopes = Array.isArray(payload.envelopes) && payload.envelopes.length > 0
    ? payload.envelopes
    : [payload.envelope].filter(Boolean);
  if (envelopes.length === 0) {
    throw new Error("no envelopes provided");
  }
  // Always "preferred" — matches enroll. Touch ID always does UV
  // anyway (PRF stable); YubiKey 5.4+ without PIN falls through to UP
  // and stays on CredRandomWithoutUV (also stable).
  const uvMode = "preferred";

  setStatus(
    envelopes.length === 1
      ? "asserting credential — confirm with biometric or tap your security key…"
      : `tap any of your ${envelopes.length} enrolled authenticators…`,
  );

  // Build allowCredentials + per-credential PRF salts in one ceremony.
  // WebAuthn's prf.evalByCredential lets the authenticator-of-the-user's-
  // choice get the right salt without us knowing in advance which one
  // they'll tap.
  const allowCredentials = envelopes.map((e) => ({
    type: "public-key",
    id: b64urlDecode(e.credentialId),
  }));
  const evalByCredential = {};
  for (const e of envelopes) {
    evalByCredential[e.credentialId] = { first: b64urlDecode(e.prfSalt) };
  }
  // For single-envelope (legacy path), `eval` alone is enough; for multi
  // we use `evalByCredential`. Include both to be permissive.
  const prfExt =
    envelopes.length === 1
      ? { eval: { first: b64urlDecode(envelopes[0].prfSalt) } }
      : { evalByCredential };

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials,
      userVerification: uvMode,
      extensions: { prf: prfExt },
      timeout: 60000,
    },
  });
  const prfResults = assertion.getClientExtensionResults().prf;
  const prfFirst = prfResults && prfResults.results && prfResults.results.first;
  if (!prfFirst) {
    throw new Error("PRF evaluation failed — this device may not support it");
  }

  // Match the asserted credentialId against our envelope set to find the
  // wrap to decrypt.
  const usedIdB64u = b64urlEncode(assertion.rawId);
  const matched = envelopes.find((e) => e.credentialId === usedIdB64u);
  if (!matched) {
    throw new Error("asserted credential did not match any enrolled authenticator");
  }

  const aesKey = await crypto.subtle.importKey(
    "raw",
    prfFirst,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const ikm = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64urlDecode(matched.wrapIv) },
      aesKey,
      b64urlDecode(matched.wrappedIkm),
    ),
  );

  setStatus("unwrapped vault key — handing back to extension…", "ok");
  post({ kind: "unlocked", ikm: b64urlEncode(ikm), credentialId: usedIdB64u });
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
      // mode: "key" | "platform" — default to legacy "key" for back-compat
      await doEnroll(event.data.ikm, event.data.mode);
    } else if (action === "unlock") {
      msgEl.textContent = "Unlocking your vault…";
      // Pass the whole event.data so doUnlock can pick envelope (legacy)
      // or envelopes (v3) without us pre-flattening.
      await doUnlock(event.data);
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
