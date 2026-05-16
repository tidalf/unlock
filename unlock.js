// rustofill biometric unlock page. Hosted at https://tidalf.github.io/unlock/.
// The extension opens this page in a new window; the bio-bridge content
// script on this origin relays messages between the page and the SW.
//
// Protocol (v3 — page is crypto-free; SW does all wrapping/unwrapping):
//   action=enroll   → WebAuthn create + PRF eval on DISCOVERY_SALT.
//                     Returns {credentialId, prfOutput} to the SW.
//   action=unlock   → WebAuthn get with allowCredentials and per-credential
//                     prfSalt via evalByCredential. Returns
//                     {credentialId, prfOutput}.
//   action=discover → Discoverable WebAuthn get (no allowCredentials),
//                     PRF eval on DISCOVERY_SALT. Returns
//                     {credentialId, prfOutput} for whichever credential
//                     the user picked.
//
// The IKM never crosses this page in v3. Everything keyed off prfOutput is
// computed on the SW side (envelope wrap/unwrap, discovery pubkey,
// discovery encryption). The page is intentionally minimal.

const msgEl = document.getElementById("msg");
const statusEl = document.getElementById("status");

// DISCOVERY_SALT = SHA-256("rustofill-prf-v1"). Constant across all installs;
// allows the same authenticator to land on the same Nostr pubkey on every
// device so a discoverable get() can find the published envelope.
let DISCOVERY_SALT = null;
async function initDiscoverySalt() {
  if (DISCOVERY_SALT) return;
  DISCOVERY_SALT = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode("rustofill-prf-v1")),
  );
}

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

async function doEnroll() {
  await initDiscoverySalt();
  setStatus("creating a credential — confirm with biometric, Touch ID, or tap your security key…");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: "rustofill", id: location.hostname },
      user: { id: userId, name: "rustofill", displayName: "rustofill vault" },
      challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: {
        // "preferred" stores discoverable when the authenticator can, so a
        // future device-2 setup can find this credential with a single
        // discoverable get() — no allowCredentials, no sync code.
        residentKey: "preferred",
        userVerification: "preferred",
      },
      // Surface whether the cred actually landed discoverable. Touch ID /
      // iCloud Keychain: yes. YubiKey 5 with slots: yes. YubiKey 5 with
      // 25 slots full: silently non-discoverable (Discover won't find it).
      extensions: {
        prf: { eval: { first: DISCOVERY_SALT } },
        credProps: true,
      },
      timeout: 60000,
    },
  });
  if (!cred) throw new Error("credential creation cancelled");

  let prfFirst;
  const createPrf = cred.getClientExtensionResults().prf;
  if (createPrf && createPrf.results && createPrf.results.first) {
    prfFirst = createPrf.results.first;
  } else {
    // Older browsers / authenticators don't support prf-on-create; do a
    // follow-up get() with the freshly created credential.
    setStatus("deriving wrapping key — confirm again…");
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: cred.rawId }],
        userVerification: "preferred",
        extensions: { prf: { eval: { first: DISCOVERY_SALT } } },
        timeout: 60000,
      },
    });
    const r = assertion.getClientExtensionResults().prf;
    prfFirst = r && r.results && r.results.first;
  }
  if (!prfFirst) {
    throw new Error("this device or browser doesn't support the WebAuthn PRF extension");
  }

  const credProps = cred.getClientExtensionResults().credProps;
  const discoverable = credProps && credProps.rk === true;

  setStatus("authenticator enrolled — handing back to extension…", "ok");
  post({
    kind: "enrolled",
    credentialId: b64urlEncode(cred.rawId),
    prfOutput: b64urlEncode(prfFirst),
    discoverable: !!discoverable,
  });
  msgEl.textContent = "All done. You can close this window.";
  setTimeout(() => {
    try {
      window.close();
    } catch (_e) {}
  }, 1200);
}

async function doUnlock(payload) {
  await initDiscoverySalt();
  // SW passes the wrappers' (credentialId, prfSalt) pairs so we can build
  // allowCredentials + evalByCredential. SW is responsible for unwrapping
  // wrappedIkm using the prfOutput we return below.
  const envelopes = Array.isArray(payload.envelopes) && payload.envelopes.length > 0
    ? payload.envelopes
    : [payload.envelope].filter(Boolean);
  if (envelopes.length === 0) throw new Error("no envelopes provided");

  setStatus(
    envelopes.length === 1
      ? "asserting credential — confirm with biometric or tap your security key…"
      : `tap any of your ${envelopes.length} enrolled authenticators…`,
  );

  const allowCredentials = envelopes.map((e) => ({
    type: "public-key",
    id: b64urlDecode(e.credentialId),
  }));
  // evalByCredential supports per-credential PRF salts in one ceremony, so
  // mixed v1 (random salt) and v2 (constant DISCOVERY_SALT) wrappers can
  // coexist on the same vault and unlock in one tap.
  const evalByCredential = {};
  for (const e of envelopes) {
    evalByCredential[e.credentialId] = { first: b64urlDecode(e.prfSalt) };
  }
  const prfExt =
    envelopes.length === 1
      ? { eval: { first: b64urlDecode(envelopes[0].prfSalt) } }
      : { evalByCredential };

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials,
      userVerification: "preferred",
      extensions: { prf: prfExt },
      timeout: 60000,
    },
  });
  const prfResults = assertion.getClientExtensionResults().prf;
  const prfFirst = prfResults && prfResults.results && prfResults.results.first;
  if (!prfFirst) {
    throw new Error("PRF evaluation failed — this device may not support it");
  }

  setStatus("got prf output — handing back to extension…", "ok");
  post({
    kind: "unlocked",
    credentialId: b64urlEncode(assertion.rawId),
    prfOutput: b64urlEncode(prfFirst),
  });
  msgEl.textContent = "All done. You can close this window.";
  setTimeout(() => {
    try {
      window.close();
    } catch (_e) {}
  }, 1200);
}

async function doDiscover() {
  await initDiscoverySalt();
  setStatus("tap your authenticator — looking for an enrolled rustofill credential…");

  // Discoverable get: no allowCredentials. The authenticator will offer any
  // resident credential it has for this rp.id. PRF evaluates on the
  // well-known DISCOVERY_SALT so the prfOutput matches what device 1 used
  // to derive the discovery pubkey + envelope wrap key.
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: "preferred",
      extensions: { prf: { eval: { first: DISCOVERY_SALT } } },
      timeout: 60000,
    },
  });
  const prfResults = assertion.getClientExtensionResults().prf;
  const prfFirst = prfResults && prfResults.results && prfResults.results.first;
  if (!prfFirst) {
    throw new Error("PRF evaluation failed — this device may not support it");
  }

  setStatus("got prf output — fetching envelope from relays…", "ok");
  post({
    kind: "discovered",
    credentialId: b64urlEncode(assertion.rawId),
    prfOutput: b64urlEncode(prfFirst),
  });
  msgEl.textContent = "All done. You can close this window.";
  setTimeout(() => {
    try {
      window.close();
    } catch (_e) {}
  }, 1200);
}

window.addEventListener("message", async (event) => {
  if (event.source !== window) return;
  if (event.data?.source !== "rustofill-ext") return;
  const { action } = event.data;
  try {
    if (action === "enroll") {
      msgEl.textContent = "Enrolling authenticator…";
      await doEnroll();
    } else if (action === "unlock") {
      msgEl.textContent = "Unlocking your vault…";
      await doUnlock(event.data);
    } else if (action === "discover") {
      msgEl.textContent = "Discovering your vault…";
      await doDiscover();
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
