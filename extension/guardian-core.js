"use strict";

// Shared policy helpers. No page content is accessed.
globalThis.Guardian = {
  threshold: 60,
  suppressionMs: 5 * 60 * 1000,
  origin(url) {
    try {
      const parsed = new URL(url);
      if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) return null;
      return parsed.origin;
    } catch {
      return null;
    }
  },
  pattern(origin) {
    const url = new URL(origin);
    // Chrome host permissions cover all ports; policy still checks exact origins.
    return `${url.protocol}//${url.hostname}/*`;
  },
  validResult(data) {
    return data && Number.isInteger(data.sus_score) && data.sus_score >= 0 &&
      data.sus_score <= 100 && ["low", "review", "high", "critical"].includes(data.risk_level) &&
      Array.isArray(data.indicators) && data.indicators.every((item) => typeof item === "string") &&
      typeof data.message === "string";
  },
  // Monitoring modes
  Mode: { OFF: "OFF", SELECTED_WEBSITES: "SELECTED_WEBSITES", ALL_WEBSITES: "ALL_WEBSITES" },
  // Automatic monitoring sends only the website origin.
  minimizeUrl(url) {
    return this.origin(url);
  },
  // Fingerprints prevent full URLs being retained in session storage.
  async fingerprint(url) {
    if (!this.origin(url)) return null;
    const bytes = new TextEncoder().encode(url);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");
  },
  // Risk badge mapping for extension action
  riskBadge(score) {
    if (score === null || score === undefined) return { text: "?", color: "#6b7280", title: "UNAVAILABLE" };
    if (score < 20) return { text: "LOW", color: "#16a34a", title: "LOW" };
    if (score < 40) return { text: "REV", color: "#ca8a04", title: "REVIEW" };
    if (score < 60) return { text: "REV", color: "#ca8a04", title: "REVIEW" };
    if (score < 80) return { text: "HIGH", color: "#dc2626", title: "HIGH" };
    return { text: "CRIT", color: "#dc2626", title: "CRITICAL" };
  },
};
