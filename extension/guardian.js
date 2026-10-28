"use strict";

importScripts("guardian-core.js");

const pending = new Map();
let revision = 0;
let settingsQueue = Promise.resolve();
let sessionQueue = Promise.resolve();

async function settings() {
  const saved = await chrome.storage.local.get({ guardianEnabled: false, approvedOrigins: [] });
  return { enabled: saved.guardianEnabled === true, origins: saved.approvedOrigins };
}

async function allowed(url) {
  const origin = Guardian.origin(url);
  const state = await settings();
  return Boolean(origin && state.enabled && state.origins.includes(origin) &&
    await chrome.permissions.contains({ origins: [Guardian.pattern(origin)] }));
}

function updateSession(change) {
  const task = sessionQueue.then(async () => {
    const state = await chrome.storage.session.get({ results: {}, suppressed: {} });
    const now = Date.now();
    state.suppressed = Object.fromEntries(Object.entries(state.suppressed)
      .filter(([, until]) => until > now).slice(-100));
    await change(state);
    await chrome.storage.session.set(state);
  });
  sessionQueue = task.catch(() => {});
  return task;
}

// These functions run in Chrome's isolated world, only on approved hosts.
// They create/remove our own UI; they never inspect page text or form fields.
function removeWarning() {
  document.getElementById("sus-not-guardian-warning-v1")?.remove();
}

function showWarning(data, expectedUrl) {
  if (location.href !== expectedUrl) return;
  const id = "sus-not-guardian-warning-v1";
  document.getElementById(id)?.remove();
  const host = document.createElement("div");
  host.id = id;
  host.style.cssText = "all:initial!important;position:fixed!important;top:16px!important;right:16px!important;z-index:2147483647!important;display:block!important;";
  const root = host.attachShadow({ mode: "closed" });
  const panel = document.createElement("section");
  panel.setAttribute("role", "alert");
  panel.style.cssText = "font:14px/1.5 system-ui,sans-serif;color:#172033;background:#fff5dc;border:3px solid #a34b00;border-radius:8px;padding:16px;width:320px;max-width:80vw;max-height:70vh;overflow:auto;box-shadow:0 4px 24px #0005";
  const title = document.createElement("strong");
  title.textContent = `SUS.NOT Guardian — SUS Score ${data.sus_score} / 100`;
  panel.append(title);
  const explanation = document.createElement("p");
  explanation.textContent = "Preliminary heuristic assessment, not proof of malicious activity. This website is not blocked. A low score does not guarantee safety.";
  panel.append(explanation);
  const list = document.createElement("ul");
  for (const text of data.indicators.length ? data.indicators : ["None detected."]) {
    const item = document.createElement("li");
    item.textContent = text;
    list.append(item);
  }
  panel.append(list);
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.textContent = "Dismiss warning";
  dismiss.style.cssText = "font:inherit;padding:8px;cursor:pointer";
  dismiss.addEventListener("click", () => host.remove());
  panel.append(dismiss);
  root.append(panel);
  document.documentElement.append(host);
  // Same-document navigation must not leave a warning for the previous URL.
  const lifetime = setInterval(() => {
    if (!host.isConnected || location.href !== expectedUrl) {
      host.remove();
      clearInterval(lifetime);
    }
  }, 500);
}

async function clearWarnings() {
  const state = await settings();
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map(async (tab) => {
    const origin = Guardian.origin(tab.url);
    if (!origin || !state.origins.includes(origin)) return;
    if (!await chrome.permissions.contains({ origins: [Guardian.pattern(origin)] })) return;
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: removeWarning }).catch(() => {});
  }));
}

async function analyze(tabId, url) {
  if (!await allowed(url)) return;
  if (pending.get(tabId)?.url === url) return;
  pending.get(tabId)?.controller.abort();
  const controller = new AbortController();
  const job = { url, controller, revision };
  pending.set(tabId, job);
  const timer = setTimeout(() => controller.abort(), 10000);
  const stillCurrent = async () => {
    if (job.revision !== revision || pending.get(tabId) !== job || !await allowed(url)) return false;
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    // Settings can change while either Chrome API call above is awaiting.
    return job.revision === revision && pending.get(tabId) === job && tab?.url === url;
  };
  try {
    // Check again immediately before sending, including navigation/setting races.
    if (!await stillCurrent()) return;
    const response = await fetch("http://127.0.0.1:8000/analyze-url", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }), credentials: "omit", redirect: "error",
      cache: "no-store", signal: controller.signal,
    });
    if (!response.ok) throw new Error("Backend unavailable");
    const data = await response.json();
    if (!Guardian.validResult(data)) throw new Error("Unexpected backend response");
    if (!await stillCurrent()) return;
    let warn = false;
    let suppressionUntil;
    await updateSession((state) => {
      if (job.revision !== revision || pending.get(tabId) !== job) return;
      state.results[tabId] = { url, data };
      if (data.sus_score >= Guardian.threshold && !state.suppressed[url]) {
        suppressionUntil = Date.now() + Guardian.suppressionMs;
        state.suppressed[url] = suppressionUntil;
        warn = true;
      }
    });
    if (!warn || !await stillCurrent()) return;
    try {
      await chrome.scripting.executeScript({ target: { tabId }, func: showWarning, args: [data, url] });
    } catch {
      // A UI/host-access failure must not discard a successful backend assessment.
      await updateSession((state) => {
        if (state.suppressed[url] === suppressionUntil) delete state.suppressed[url];
        if (job.revision === revision && pending.get(tabId) === job && state.results[tabId]?.url === url) {
          state.results[tabId].warningError = "Automatic assessment complete, but the page warning could not be displayed. Review the score and indicators below.";
        }
      });
      return;
    }
    // If disabling raced with injection, remove the newly injected warning too.
    if (!await stillCurrent()) {
      const tab = await chrome.tabs.get(tabId).catch(() => null);
      const origin = Guardian.origin(tab?.url);
      const state = await settings();
      if (origin && state.origins.includes(origin) &&
          await chrome.permissions.contains({ origins: [Guardian.pattern(origin)] })) {
        await chrome.scripting.executeScript({ target: { tabId }, func: removeWarning });
      }
    }
  } catch {
    if (await stillCurrent()) {
      await updateSession((state) => {
        if (job.revision === revision && pending.get(tabId) === job) state.results[tabId] = { url, error: "Automatic analysis unavailable. Check the local backend or use Analyze URL to retry." };
      });
    }
  } finally {
    clearTimeout(timer);
    if (pending.get(tabId) === job) pending.delete(tabId);
  }
}

function invalidate() {
  revision++;
  for (const job of pending.values()) job.controller.abort();
  pending.clear();
}

chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.url || change.status === "loading" || change.status === "complete") {
    // A same-URL reload often has no change.url. Cancel the old document's job
    // on loading too, so completion cannot deduplicate against stale work.
    if (change.url || change.status === "loading") {
      pending.get(tabId)?.controller.abort();
      pending.delete(tabId);
      void updateSession((state) => { delete state.results[tabId]; });
    }
    // Analyze only the completed top-level document (also handles same-document URLs).
    if (tab.status === "complete" && tab.url) void analyze(tabId, tab.url).catch(() => {});
  }
});
chrome.tabs.onRemoved.addListener((tabId) => {
  pending.get(tabId)?.controller.abort();
  pending.delete(tabId);
  void updateSession((state) => { delete state.results[tabId]; });
});

async function handleMessage(message) {
  if (message.type === "guardian-state") {
    const state = await settings();
    const { results = {} } = await chrome.storage.session.get("results");
    const entry = results[message.tabId];
    return { ...state, result: state.enabled && entry?.url === message.url ? entry : null };
  }
  if (message.type === "guardian-enable") {
    const origin = Guardian.origin(message.url);
    if (!origin || !await chrome.permissions.contains({ origins: [Guardian.pattern(origin)] })) {
      throw new Error("Website permission is required before enabling monitoring.");
    }
    const state = await settings();
    await chrome.storage.local.set({ guardianEnabled: true, approvedOrigins: [...new Set([...state.origins, origin])] });
    return { ok: true };
  }
  if (message.type === "guardian-disable") {
    invalidate();
    await chrome.storage.local.set({ guardianEnabled: false });
    await clearWarnings();
    await updateSession((state) => { state.results = {}; state.suppressed = {}; });
    return { ok: true };
  }
  if (message.type === "guardian-revoke") {
    invalidate();
    // Remove existing UI before relinquishing the permission needed to remove it.
    await clearWarnings();
    const state = await settings();
    if (!state.origins.includes(message.origin)) throw new Error("Unknown approved origin");
    const origins = state.origins.filter((origin) => origin !== message.origin);
    await chrome.storage.local.set({ approvedOrigins: origins });
    if (!origins.some((origin) => Guardian.pattern(origin) === Guardian.pattern(message.origin))) {
      await chrome.permissions.remove({ origins: [Guardian.pattern(message.origin)] });
    }
    await updateSession((session) => { session.results = {}; session.suppressed = {}; });
    return { ok: true };
  }
  throw new Error("Unknown request");
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL("popup.html")) return false;
  const task = settingsQueue.then(() => handleMessage(message));
  settingsQueue = task.catch(() => {});
  task.then(respond, () => respond({ error: "Guardian settings could not be updated. Please retry." }));
  return true;
});

// Respect permissions revoked through Chrome's own extension controls as well.
chrome.permissions.onRemoved.addListener(() => {
  const task = settingsQueue.then(async () => {
    invalidate();
    const state = await settings();
    const origins = [];
    for (const origin of state.origins) {
      if (await chrome.permissions.contains({ origins: [Guardian.pattern(origin)] })) origins.push(origin);
    }
    await chrome.storage.local.set({ approvedOrigins: origins });
    await updateSession((session) => { session.results = {}; session.suppressed = {}; });
  });
  settingsQueue = task.catch(() => {});
});
