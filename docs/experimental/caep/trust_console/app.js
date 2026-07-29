"use strict";

const state = { records: [], activeIndex: 0, sourceName: "" };
const $ = (id) => document.getElementById(id);

const STATUS_COPY = {
  verified: { tone: "success", icon: "✓", badge: "Verified", kicker: "Operation independently verified", heading: "The requested outcome was achieved.", trusted: "The declared business outcome passed independent verification." },
  recovered: { tone: "success", icon: "↺", badge: "Recovered", kicker: "Divergence detected and repaired", heading: "The system restored the intended outcome.", trusted: "The smallest justified compensating action restored the target state and the result was independently verified." },
  contained: { tone: "warning", icon: "!", badge: "Contained", kicker: "Business outcome diverged", heading: "The tool succeeded, but the intended result did not.", trusted: "Further harm was contained. Recovery remains required before this operation can be accepted." },
  completed: { tone: "warning", icon: "…", badge: "Completed", kicker: "Tool execution completed", heading: "The tool completed, but the business result is not independently accepted.", trusted: "Independent postcondition verification has not established the final user outcome." },
  blocked: { tone: "danger", icon: "×", badge: "Blocked", kicker: "Action was not permitted", heading: "The requested action was blocked before dispatch.", trusted: "No accepted transition was performed." }
};

function normalizeInput(value) {
  if (Array.isArray(value)) return value.filter(isCaepRecord);
  if (isCaepRecord(value)) return [value];
  if (Array.isArray(value?.records)) return value.records.filter(isCaepRecord);
  const candidates = [];
  const visit = (node) => {
    if (!node || typeof node !== "object") return;
    if (isCaepRecord(node)) { candidates.push(node); return; }
    for (const child of Object.values(node)) if (child && typeof child === "object") visit(child);
  };
  visit(value);
  const seen = new Set();
  return candidates.filter((record) => !seen.has(record.episode_id) && seen.add(record.episode_id));
}

function isCaepRecord(value) {
  return Boolean(value && typeof value === "object" && value.profile === "org.causal-memory-layer.caep" && value.episode_id);
}

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

function titleCase(value) {
  return String(value || "unknown").replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function shortRef(value) {
  const text = String(value || "Not declared");
  const pieces = text.split(/[/:]/).filter(Boolean);
  return pieces.at(-1) || text;
}

function formatTime(value) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

function canonicalRecord(record) {
  const clone = structuredClone(record);
  if (clone.integrity) {
    delete clone.integrity.record_digest;
    delete clone.integrity.signature;
  }
  return stableStringify(clone);
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

async function sha256Hex(text) {
  if (!globalThis.crypto?.subtle) return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function verifyIntegrity(record) {
  const declared = record.integrity?.record_digest?.value?.toLowerCase();
  const computed = await sha256Hex(canonicalRecord(record));
  const parents = record.causal_parent_ids || [];
  const bindings = record.integrity?.parent_digests || {};
  const keysMatch = parents.length === Object.keys(bindings).length && parents.every((id) => bindings[id]);
  if (!computed || !declared) return { state: "unknown", label: "Digest not checked", computed, keysMatch };
  return { state: computed === declared && keysMatch ? "success" : "danger", label: computed === declared && keysMatch ? "Record digest matches" : "Digest or parent binding mismatch", computed, keysMatch };
}

function loadValue(value, sourceName = "Loaded JSON") {
  const records = normalizeInput(value);
  if (!records.length) throw new Error("No CAEP records were found in this JSON.");
  state.records = records;
  state.activeIndex = Math.max(0, records.findIndex((record) => ["recovered", "verified"].includes(record.status)));
  state.sourceName = sourceName;
  $("workspace").hidden = false;
  $("emptyState").hidden = true;
  $("bundleTitle").textContent = records.length === 1 ? "Trust receipt" : `${records.length} linked trust receipts`;
  $("bundleSubtitle").textContent = `${sourceName} · ${records[0].workflow_id || "workflow not declared"}`;
  renderTabs();
  renderActiveRecord();
  $("workspace").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderTabs() {
  $("recordTabs").innerHTML = state.records.map((record, index) => {
    const label = `${titleCase(record.status)} · ${shortRef(record.action?.dispatch?.tool_name || record.episode_id)}`;
    return `<button class="record-tab" role="tab" aria-selected="${index === state.activeIndex}" data-index="${index}">${escapeHtml(label)}</button>`;
  }).join("");
  $("recordTabs").querySelectorAll(".record-tab").forEach((button) => {
    button.addEventListener("click", () => { state.activeIndex = Number(button.dataset.index); renderTabs(); renderActiveRecord(); });
  });
}

async function renderActiveRecord() {
  const record = state.records[state.activeIndex];
  const copy = STATUS_COPY[record.status] || STATUS_COPY.completed;
  const verification = record.verification || {};
  const checks = verification.checks || [];
  const criticalIds = new Set((record.expected_postconditions || []).filter((item) => item.severity === "critical").map((item) => item.id));
  const criticalChecks = checks.filter((check) => criticalIds.has(check.postcondition_id));
  const passedCritical = criticalChecks.filter((check) => check.result === "pass").length;
  const parents = record.causal_parent_ids || [];

  $("statusBadge").textContent = copy.badge;
  $("statusBadge").dataset.tone = copy.tone === "success" ? "" : copy.tone;
  $("receiptIcon").textContent = copy.icon;
  $("receiptIcon").dataset.tone = copy.tone === "success" ? "" : copy.tone;
  $("receiptKicker").textContent = copy.kicker;
  $("receiptHeading").textContent = copy.heading;
  $("receiptSummary").textContent = humanSummary(record);
  $("episodeId").textContent = record.episode_id;

  $("intentSummary").textContent = record.intent?.summary || titleCase(record.intent?.code);
  $("intentConstraints").innerHTML = (record.intent?.constraints || []).map((item) => `<span class="tag">${escapeHtml(item)}</span>`).join("") || '<span class="tag">No constraints declared</span>';
  $("outcomeSummary").textContent = outcomeSummary(record);
  $("toolName").textContent = record.action?.dispatch?.tool_name || "No dispatch";
  $("toolResult").textContent = titleCase(record.outcome?.status || "not performed");
  $("recoveryActions").innerHTML = recoveryActions(record).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  $("trustedState").textContent = copy.trusted;
  $("verifierSummary").textContent = verifierText(record);

  $("intentMetric").textContent = ["verified", "recovered"].includes(record.status) ? "Confirmed" : "Not accepted";
  $("intentMetricNote").textContent = record.intent?.code || "No intent code";
  $("verificationMetric").textContent = verification.independence === "independent" ? "Independent" : titleCase(verification.independence || "missing");
  $("verificationMetricNote").textContent = shortRef(verification.verifier?.ref);
  $("criticalMetric").textContent = criticalIds.size ? `${passedCritical} / ${criticalIds.size} pass` : "None declared";
  $("criticalMetricNote").textContent = verification.verdict ? `Verdict: ${verification.verdict}` : "No verification verdict";
  $("lineageMetric").textContent = parents.length ? `${parents.length} parent bound` : "Root record";
  $("lineageMetricNote").textContent = parents.length ? parents.join(", ") : "No causal parent required";

  renderTimeline(record);
  renderEvidence(record);
  $("rawJson").querySelector("code").textContent = JSON.stringify(record, null, 2);
  $("rawJson").hidden = true;
  $("toggleJsonButton").textContent = "Show raw record";
  $("toggleJsonButton").setAttribute("aria-expanded", "false");

  const integrity = await verifyIntegrity(record);
  $("integrityBadge").textContent = integrity.label;
  $("integrityBadge").dataset.tone = integrity.state;
  renderIntegrityDetails(record, integrity);
}

function humanSummary(record) {
  if (record.status === "recovered") return "A duplicate or otherwise invalid state was detected, the bounded compensating action was executed, and the final business condition passed independent verification.";
  if (record.status === "contained") return "The tool reported success, but an independent verifier found that the critical business condition failed. Further actions were contained.";
  if (record.status === "verified") return "The tool result and the independently observed business state agree with the user’s declared intent.";
  return record.decision?.summary || "This record describes one auditable action episode.";
}

function outcomeSummary(record) {
  const tool = record.action?.dispatch?.tool_name || "No tool";
  const status = record.outcome?.status || "not performed";
  const verdict = record.verification?.verdict || "not verified";
  if (status === "succeeded" && verdict === "diverged") return `${tool} returned success, but independent verification found that the business postcondition failed.`;
  return `${tool} reported ${status}; the recorded verification verdict is ${verdict}.`;
}

function recoveryActions(record) {
  const actions = [];
  if (record.status === "contained") actions.push("Blocked further retries or downstream harm.");
  if (record.recovery?.action_refs?.length) actions.push(...record.recovery.action_refs.map((ref) => describeActionRef(ref)));
  if (record.action?.dispatch?.tool_name) actions.push(`Executed ${record.action.dispatch.tool_name} as the bounded transition.`);
  if (record.verification?.verdict) actions.push(`Recorded an independent ${record.verification.verdict} verification verdict.`);
  return [...new Set(actions)].slice(0, 5);
}

function describeActionRef(ref) {
  const value = shortRef(ref).replaceAll("-", " ").replaceAll("_", " ");
  return titleCase(value) + ".";
}

function verifierText(record) {
  const verification = record.verification;
  if (!verification) return "No independent verification was recorded.";
  const actor = shortRef(verification.verifier?.ref);
  return `${actor} · ${titleCase(verification.verdict)} at ${formatTime(verification.verified_at)}`;
}

function renderTimeline(record) {
  const nodes = [
    ["Intent", titleCase(record.intent?.code), record.intent?.summary || "Intent declared"],
    ["Authorization", titleCase(record.authorization?.decision), `Scope: ${record.authorization?.scope?.action || "not declared"}`],
    ["Decision", titleCase(record.decision?.code), record.decision?.summary || "Decision recorded"],
    ["Dispatch", record.action?.dispatch?.tool_name || "No dispatch", `Executor: ${shortRef(record.action?.dispatch?.executor?.ref)}`],
    ["Verification", titleCase(record.verification?.verdict || "not performed"), `${record.verification?.checks?.length || 0} postcondition check(s)`]
  ];
  $("causalTimeline").innerHTML = nodes.map(([stage, title, text]) => `<article class="timeline-node"><span>${escapeHtml(stage)}</span><h3>${escapeHtml(title)}</h3><p>${escapeHtml(text)}</p></article>`).join("");
}

function detailRows(rows) {
  return rows.map(([term, value]) => `<div><dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("");
}

function renderEvidence(record) {
  $("actorsList").innerHTML = detailRows([
    ["Initiator", shortRef(record.intent?.initiator?.ref)], ["Policy actor", shortRef(record.authorization?.actor?.ref)], ["Decision maker", shortRef(record.decision?.maker?.ref)], ["Executor", shortRef(record.action?.dispatch?.executor?.ref)], ["Verifier", shortRef(record.verification?.verifier?.ref)]
  ]);
  $("timingList").innerHTML = detailRows([
    ["Dispatch started", formatTime(record.action?.dispatch?.started_at)], ["Dispatch completed", formatTime(record.action?.dispatch?.completed_at)], ["Outcome observed", formatTime(record.outcome?.observed_at)], ["Verified", formatTime(record.verification?.verified_at)], ["Record time", formatTime(record.time?.recorded_time)]
  ]);
  const postconditions = new Map((record.expected_postconditions || []).map((item) => [item.id, item]));
  $("checksList").innerHTML = (record.verification?.checks || []).map((check) => {
    const condition = postconditions.get(check.postcondition_id);
    const passed = check.result === "pass";
    return `<div class="check-row"><span class="check-result" data-tone="${passed ? "success" : "danger"}">${passed ? "✓" : "×"}</span><div><strong>${escapeHtml(check.postcondition_id)}</strong><small>${escapeHtml(`${titleCase(check.result)} · ${condition?.severity || "severity unknown"}`)}</small></div></div>`;
  }).join("") || "<p>No verification checks recorded.</p>";
}

function renderIntegrityDetails(record, integrity) {
  $("integrityList").innerHTML = detailRows([
    ["Declared digest", record.integrity?.record_digest?.value || "Missing"], ["Computed digest", integrity.computed || "Unavailable in this browser context"], ["Parent keys", integrity.keysMatch ? "Consistent" : "Mismatch"], ["Canonicalization", record.integrity?.canonicalization || "Not declared"], ["Signature", record.integrity?.signature ? "Present (not verified here)" : "Not present"]
  ]);
}

function receiptPayload(record) {
  return {
    generated_at: new Date().toISOString(), source: state.sourceName, episode_id: record.episode_id, workflow_id: record.workflow_id, status: record.status,
    intent: record.intent?.summary || record.intent?.code, action: record.action?.dispatch?.tool_name || null, tool_outcome: record.outcome?.status || null,
    verification: record.verification?.verdict || null, independent_verifier: record.verification?.verifier?.ref || null, recovery_status: record.recovery?.status || null,
    causal_parent_ids: record.causal_parent_ids || [], record_digest: record.integrity?.record_digest || null,
    notice: "Human-readable receipt generated from CAEP evidence. Integrity is not authenticity; signatures are not verified by this viewer."
  };
}

function downloadJson(filename, value) {
  const blob = new Blob([JSON.stringify(value, null, 2) + "\n"], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

$("fileInput").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try { loadValue(JSON.parse(await file.text()), file.name); }
  catch (error) { alert(`Could not open CAEP file: ${error.message}`); }
  event.target.value = "";
});
$("loadDemoButton").addEventListener("click", () => loadValue(window.CAEP_DEMO_BUNDLE, "Built-in recovery demo"));
$("pasteButton").addEventListener("click", () => { $("pasteError").textContent = ""; $("pasteDialog").showModal(); $("pasteInput").focus(); });
$("parsePasteButton").addEventListener("click", () => {
  try { loadValue(JSON.parse($("pasteInput").value), "Pasted JSON"); $("pasteDialog").close(); }
  catch (error) { $("pasteError").textContent = error.message; }
});
$("printButton").addEventListener("click", () => window.print());
$("downloadButton").addEventListener("click", () => {
  const record = state.records[state.activeIndex];
  downloadJson(`${record.episode_id}-trust-receipt.json`, receiptPayload(record));
});
$("toggleJsonButton").addEventListener("click", () => {
  const nextHidden = !$("rawJson").hidden;
  $("rawJson").hidden = nextHidden;
  $("toggleJsonButton").textContent = nextHidden ? "Show raw record" : "Hide raw record";
  $("toggleJsonButton").setAttribute("aria-expanded", String(!nextHidden));
});
