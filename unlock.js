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
  setStatus("creating a credential — confirm with biometric or insert + tap your security key…");
  const ikm = b64urlDecode(ikmB64u);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  // Salt the PRF on enroll so we evaluate in a single ceremony when the
  // authenticator supports prf-on-create (Chrome 116+ + YubiKey 5.4+).
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));

  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: "rustofill", id: location.hostname },
      user: { id: userId, name: "rustofill", displayName: "rustofill vault" },
      challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: {
        // No authenticatorAttachment — browser shows the chooser with both
        // platform (Touch ID, Hello) and roaming (YubiKey 5.4+, etc.)
        // options.
        residentKey: "discouraged", // we always know the credentialId at unlock
        // CTAP 2.1 split hmac-secret into CredRandomWithUV (used when UV is
        // performed — PIN-derived) and CredRandomWithoutUV (used without
        // UV — touch-only). "discouraged" requests the no-UV path so
        // YubiKey 5.4+ produces a touch-only PRF and skips the PIN.
        //
        // Important catch: pre-CTAP-2.1 YubiKeys (firmware < 5.4) ONLY
        // have CredRandomWithUV — they don't support a no-UV hmac-secret
        // path at all, so the authenticator will require PIN regardless
        // of what we ask. You can detect this hardware: `ykman fido
        // config toggle-always-uv` returns "Always Require UV is not
        // supported on this YubiKey." on pre-5.4 firmware.
        //
        // On platform authenticators, "discouraged" is a near no-op: UV
        // and user presence coincide (biometric), so the user still sees
        // the Touch ID prompt either way.
        userVerification: "discouraged",
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
        userVerification: "discouraged",
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

async function doUnlock(envelope) {
  setStatus("asserting credential — confirm with biometric or tap your security key…");
  const credentialId = b64urlDecode(envelope.credentialId);
  const prfSalt = b64urlDecode(envelope.prfSalt);
  const wrappedIkm = b64urlDecode(envelope.wrappedIkm);
  const wrapIv = b64urlDecode(envelope.wrapIv);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: "public-key", id: credentialId }],
      // Must match the UV setting used at enroll — Yubico's PRF derivation
      // mixes in PIN-derived material when UV is on, so changing this
      // produces a different PRF output and the wrap won't decrypt.
      userVerification: "discouraged",
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
