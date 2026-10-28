"use strict";

// Dependency-free policy/service-worker tests, not a Chrome browser simulation.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const extension = path.join(__dirname, "../extension");

function harness() {
  const listeners = {};
  const local = {};
  const session = {};
  const permissions = new Set();
  const tabs = new Map([[1, { id: 1, url: "https://example.com/", status: "complete" }]]);
  const requests = [];
  const injections = [];
  let score = 59;
  let fetchImpl;
  let injectionFailure = false;
  function event(name) {
    const handlers = [];
    listeners[name] = (...args) => {
      let returned;
      for (const handler of handlers) returned = handler(...args);
      return returned;
    };
    return { addListener: (fn) => { handlers.push(fn); } };
  }
  function storage(values, area) {
    return {
      async get(keys) {
        if (typeof keys === "string") return { [keys]: values[keys] };
        return { ...keys, ...structuredClone(values) };
      },
      async set(next) {
        const previous = structuredClone(values);
        Object.assign(values, structuredClone(next));
        const changes = Object.fromEntries(Object.entries(next).map(([key, value]) =>
          [key, { oldValue: previous[key], newValue: structuredClone(value) }]));
        setImmediate(() => listeners.storageChanged?.(changes, area));
      },
    };
  }
  const chrome = {
    storage: { local: storage(local, "local"), session: storage(session, "session"), onChanged: event("storageChanged") },
    permissions: {
      contains: async ({ origins }) => origins.every((origin) => permissions.has(origin)),
      remove: async ({ origins }) => { origins.forEach((origin) => permissions.delete(origin)); return true; },
      onRemoved: event("permissionsRemoved"),
    },
    tabs: {
      onUpdated: event("updated"), onRemoved: event("removed"),
      query: async () => [...tabs.values()],
      get: async (id) => tabs.get(id),
    },
    scripting: { executeScript: async (details) => {
      if (injectionFailure) throw new Error("Script injection unavailable");
      injections.push(details);
    } },
    runtime: { id: "test", getURL: (file) => `chrome-extension://test/${file}`, onMessage: event("message") },
  };
  const context = vm.createContext({
    chrome, URL, AbortController, setTimeout, clearTimeout, console,
    fetch: async (url, options) => {
      requests.push({ url, options });
      if (fetchImpl) return fetchImpl(url, options);
      return { ok: true, json: async () => ({ sus_score: score, risk_level: "review", indicators: ["Test indicator"], message: "Heuristic only" }) };
    },
  });
  context.importScripts = (file) => vm.runInContext(fs.readFileSync(path.join(extension, file), "utf8"), context);
  vm.runInContext(fs.readFileSync(path.join(extension, "guardian.js"), "utf8"), context);
  const message = (data) => new Promise((resolve) => listeners.message(data,
    { id: "test", url: "chrome-extension://test/popup.html" }, resolve));
  chrome.runtime.sendMessage = message;
  const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(setImmediate); };
  const navigate = async (url) => {
    tabs.set(1, { id: 1, url, status: "complete" });
    listeners.updated(1, { url, status: "complete" }, tabs.get(1));
    await flush();
  };
  const enable = async () => {
    permissions.add("https://example.com/*");
    await message({ type: "guardian-enable", url: "https://example.com/" });
  };
  const update = async (change, url = change.url || tabs.get(1).url, status = change.status || tabs.get(1).status) => {
    tabs.set(1, { id: 1, url, status });
    listeners.updated(1, change, tabs.get(1));
    await flush();
  };
  const openPopup = async () => {
    const nodes = new Map();
    const element = () => ({ hidden: true, disabled: true, textContent: "", children: [], handlers: {},
      addEventListener(name, fn) { (this.handlers[name] ||= []).push(fn); },
      replaceChildren() { this.children = []; },
      append(...children) { this.children.push(...children); },
      appendChild(child) { this.children.push(child); },
    });
    const document = {
      getElementById(id) { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); },
      createElement: element, createTextNode: (text) => text,
    };
    const popup = vm.createContext({ document, chrome, URL, AbortSignal, fetch: context.fetch });
    for (const file of ["guardian-core.js", "popup.js", "guardian-popup.js"]) {
      vm.runInContext(fs.readFileSync(path.join(extension, file), "utf8"), popup);
    }
    await flush();
    return { nodes, click: async (id) => {
      for (const handler of nodes.get(id).handlers.click) await handler();
      await flush();
    } };
  };
  return { local, session, permissions, requests, injections, listeners, message, navigate, update, enable, flush, openPopup,
    setScore: (value) => { score = value; }, setFetch: (fn) => { fetchImpl = fn; },
    setInjectionFailure: (value) => { injectionFailure = value; } };
}

test("manifest uses MV3, optional website hosts, and only the local mandatory host", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(extension, "manifest.json"), "utf8"));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ["activeTab", "storage", "scripting"]);
  assert.deepEqual(manifest.host_permissions, ["http://127.0.0.1:8000/*"]);
  assert.deepEqual(manifest.optional_host_permissions, ["http://*/*", "https://*/*"]);
});

test("OFF by default; enable requires permission; unapproved origins are never sent", async () => {
  const h = harness();
  assert.equal((await h.message({ type: "guardian-state" })).enabled, false);
  await h.navigate("https://example.com/");
  assert.equal(h.requests.length, 0);
  assert.ok((await h.message({ type: "guardian-enable", url: "https://example.com/" })).error);
  await h.enable();
  await h.navigate("https://other.example/");
  await h.navigate("http://example.com/");
  await h.navigate("https://example.com:8443/");
  await h.navigate("https://user:secret@example.com/");
  assert.equal(h.requests.length, 0);
  await h.navigate("https://example.com/safe");
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].url, "http://127.0.0.1:8000/analyze-url");
  assert.equal(h.requests[0].options.credentials, "omit");
});

test("59 is silent and available in popup; 60 warns; repeat URL is suppressed", async () => {
  const h = harness();
  await h.enable();
  await h.navigate("https://example.com/low");
  assert.equal(h.injections.length, 0);
  const state = await h.message({ type: "guardian-state", tabId: 1, url: "https://example.com/low" });
  assert.equal(state.result.data.sus_score, 59);
  h.setScore(60);
  await h.navigate("https://example.com/high");
  assert.equal(h.injections.filter((item) => item.func.name === "showWarning").length, 1);
  await h.navigate("https://example.com/high");
  assert.equal(h.injections.filter((item) => item.func.name === "showWarning").length, 1);
  await h.navigate("https://example.com/another");
  assert.equal(h.injections.filter((item) => item.func.name === "showWarning").length, 2);
});

test("disable stops automatic requests and warnings, clears temporary results", async () => {
  const h = harness();
  await h.enable();
  h.setScore(60);
  await h.navigate("https://example.com/high");
  await h.message({ type: "guardian-disable" });
  await h.navigate("https://example.com/next");
  assert.equal(h.requests.length, 1);
  assert.equal(h.injections.filter((item) => item.func.name === "showWarning").length, 1);
  assert.equal((await h.message({ type: "guardian-state" })).enabled, false);
  assert.deepEqual(h.session.results, {});
  assert.ok(h.injections.some((item) => item.func.name === "removeWarning"));
});

test("late response after disabling cannot produce a warning or result", async () => {
  const h = harness();
  await h.enable();
  let finish;
  h.setFetch(() => new Promise((resolve) => { finish = resolve; }));
  await h.navigate("https://example.com/slow");
  await h.message({ type: "guardian-disable" });
  finish({ ok: true, json: async () => ({ sus_score: 80, risk_level: "critical", indicators: [], message: "test" }) });
  await h.flush();
  assert.equal(h.injections.filter((item) => item.func.name === "showWarning").length, 0);
  assert.deepEqual(h.session.results, {});
});

test("revocation stops monitoring even while Guardian stays enabled", async () => {
  const h = harness();
  await h.enable();
  await h.message({ type: "guardian-revoke", origin: "https://example.com" });
  assert.equal(h.permissions.size, 0);
  await h.navigate("https://example.com/next");
  assert.equal(h.requests.length, 0);
});

test("manual popup analysis still works independently of Guardian", async () => {
  const nodes = new Map();
  function element() {
    return {
      disabled: true, hidden: true, textContent: "", handlers: {}, children: [],
      addEventListener(name, fn) { this.handlers[name] = fn; },
      replaceChildren() { this.children = []; },
      appendChild(child) { this.children.push(child); },
    };
  }
  const document = {
    getElementById(id) { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); },
    createElement: element,
  };
  const requests = [];
  const context = vm.createContext({
    document, URL, AbortSignal,
    chrome: { tabs: { query: async () => [{ id: 1, url: "https://example.com/manual" }] } },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return { ok: true, json: async () => ({ sus_score: 15, risk_level: "low", indicators: ["Test"], message: "Heuristic" }) };
    },
  });
  vm.runInContext(fs.readFileSync(path.join(extension, "popup.js"), "utf8"), context);
  await vm.runInContext("currentTabReady", context);
  assert.equal(nodes.get("analyze").disabled, false);
  await nodes.get("analyze").handlers.click();
  assert.equal(requests.length, 1);
  assert.equal(JSON.parse(requests[0].options.body).url, "https://example.com/manual");
  assert.equal(nodes.get("score").textContent, "15 / 100");
  assert.equal(nodes.get("result").hidden, false);
  assert.equal(nodes.get("analyze").disabled, false);
});

test("popup requests only the current host and does not enable after permission denial", async () => {
  const nodes = new Map();
  const element = () => ({ hidden: false, disabled: false, handlers: {},
    addEventListener(name, fn) { this.handlers[name] = fn; },
    replaceChildren() {}, append() {}, textContent: "" });
  const document = {
    getElementById(id) { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); },
    createElement: element, createTextNode: (text) => text,
  };
  const requested = [];
  const messages = [];
  let granted = false;
  let enabled = false;
  const context = vm.createContext({
    document, URL, currentUrl: "https://example.com:8443/path", currentTabId: 1,
    currentTabReady: Promise.resolve(), analyzeButton: element(), result: element(), status: element(),
    renderResult() {},
    chrome: {
      tabs: { onUpdated: { addListener() {} } },
      storage: { onChanged: { addListener() {} } },
      permissions: { request: async (permission) => { requested.push(permission); return granted; } },
      runtime: { sendMessage: async (message) => {
        messages.push(message);
        if (message.type === "guardian-enable") { enabled = true; return { ok: true }; }
        return { enabled, origins: enabled ? ["https://example.com:8443"] : [] };
      } },
    },
  });
  for (const file of ["guardian-core.js", "guardian-popup.js"]) {
    vm.runInContext(fs.readFileSync(path.join(extension, file), "utf8"), context);
  }
  for (let i = 0; i < 5; i++) await new Promise(setImmediate);
  assert.equal(nodes.get("guardian-state").textContent, "OFF");
  await nodes.get("guardian-toggle").handlers.click();
  assert.equal(requested[0].origins[0], "https://example.com/*");
  assert.equal(messages.filter((message) => message.type === "guardian-enable").length, 0);
  granted = true;
  await nodes.get("guardian-toggle").handlers.click();
  assert.equal(messages.filter((message) => message.type === "guardian-enable").length, 1);
  assert.equal(nodes.get("guardian-state").textContent, "ON");
});

test("separate loading, URL and completion events analyze once, store 70, warn, and populate popup", async () => {
  const h = harness();
  assert.equal(typeof h.listeners.updated, "function", "worker registers its listener at startup");
  await h.enable();
  h.setScore(70);
  await h.update({ status: "loading" }, "https://example.com/", "loading");
  await h.update({ url: "https://example.com/automatic-70" });
  assert.equal(h.requests.length, 0);
  await h.update({ status: "complete" });
  assert.equal(h.requests.length, 1);
  assert.equal(JSON.parse(h.requests[0].options.body).url, "https://example.com/automatic-70");
  assert.equal(h.session.results[1].data.sus_score, 70);
  const warnings = h.injections.filter((item) => item.func.name === "showWarning");
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0].args[0].sus_score, 70);
  assert.equal(warnings[0].args[1], "https://example.com/automatic-70");
  const popup = await h.openPopup();
  assert.equal(popup.nodes.get("guardian-score").textContent, "70 / 100");
  assert.equal(popup.nodes.get("guardian-result").hidden, false);
  assert.equal(popup.nodes.get("result").hidden, true);
});

test("live automatic assessments remain visible after manual Analyze, without replacing manual results", async () => {
  const h = harness();
  await h.enable();
  const popup = await h.openPopup();
  assert.match(popup.nodes.get("guardian-assessment-status").textContent, /Reload or navigate/);
  await popup.click("analyze");
  assert.equal(popup.nodes.get("score").textContent, "59 / 100");
  h.setScore(70);
  await h.update({ status: "loading" });
  await h.update({ status: "complete" });
  assert.equal(popup.nodes.get("guardian-score").textContent, "70 / 100");
  assert.equal(popup.nodes.get("guardian-result").hidden, false);
  assert.equal(popup.nodes.get("score").textContent, "59 / 100");
  assert.equal(popup.nodes.get("result").hidden, false);
  h.setScore(20);
  await h.update({ url: "https://example.com/#safe" }, "https://example.com/#safe", "complete");
  assert.equal(h.session.results[1].data.sus_score, 20);
  assert.equal(popup.nodes.get("guardian-score").textContent, "20 / 100");
  assert.equal(popup.nodes.get("guardian-result").hidden, false);
  assert.equal(h.injections.filter((item) => item.func.name === "showWarning").length, 1);
  // Reopening reads the active tab URL and its latest stored assessment.
  const reopened = await h.openPopup();
  assert.equal(reopened.nodes.get("guardian-score").textContent, "20 / 100");
});

test("same-URL reload cancels stale work and completion starts a fresh assessment", async () => {
  const h = harness();
  await h.enable();
  let finish;
  h.setFetch(() => new Promise((resolve) => { finish = resolve; }));
  await h.update({ status: "complete" });
  assert.equal(h.requests.length, 1);
  await h.update({ status: "loading" });
  assert.equal(h.requests[0].options.signal.aborted, true);
  h.setFetch(null);
  h.setScore(70);
  await h.update({ status: "complete" });
  assert.equal(h.requests.length, 2);
  finish({ ok: true, json: async () => ({ sus_score: 10, risk_level: "low", indicators: [], message: "Stale" }) });
  await h.flush();
  assert.equal(h.session.results[1].data.sus_score, 70);
});

test("warning injection failure preserves score 70 in storage and popup and permits retry", async () => {
  const h = harness();
  await h.enable();
  h.setScore(70);
  h.setInjectionFailure(true);
  await h.navigate("https://example.com/injection-failure");
  assert.equal(h.session.results[1].data.sus_score, 70);
  assert.match(h.session.results[1].warningError, /warning could not be displayed/);
  assert.equal(h.session.suppressed["https://example.com/injection-failure"], undefined);
  const popup = await h.openPopup();
  assert.equal(popup.nodes.get("guardian-score").textContent, "70 / 100");
  assert.match(popup.nodes.get("guardian-assessment-status").textContent, /warning could not be displayed/);
  h.setInjectionFailure(false);
  await h.navigate("https://example.com/injection-failure");
  assert.equal(h.injections.filter((item) => item.func.name === "showWarning").length, 1);
});

test("completion events on unapproved origins or while OFF do not analyze or warn", async () => {
  const h = harness();
  h.setScore(70);
  await h.update({ status: "complete" });
  await h.enable();
  await h.update({ status: "complete" }, "https://www.example.com/", "complete");
  await h.update({ status: "complete" }, "http://example.com/", "complete");
  await h.update({ status: "complete" }, "https://example.com:8443/", "complete");
  assert.equal(h.requests.length, 0);
  await h.update({ status: "complete" }, "https://example.com/", "complete");
  assert.equal(h.requests.length, 1);
  await h.message({ type: "guardian-disable" });
  await h.update({ status: "loading" });
  await h.update({ status: "complete" });
  assert.equal(h.requests.length, 1);
  assert.equal(h.injections.filter((item) => item.func.name === "showWarning").length, 1);
});

test("backend failures are silent, with a popup error", async () => {
  const h = harness();
  await h.enable();
  h.setFetch(async () => { throw new Error("offline"); });
  await h.navigate("https://example.com/offline");
  assert.equal(h.injections.length, 0);
  assert.match(h.session.results[1].error, /unavailable/);
});
