/**
 * Webview panel that shows the CML audit summary and findings.
 */

import * as vscode from "vscode";
import { AuditResult, AuditFinding } from "../core/cli";

let currentPanel: vscode.WebviewPanel | undefined;

export function showAuditPanel(
  context: vscode.ExtensionContext,
  result: AuditResult
): void {
  if (currentPanel) {
    currentPanel.reveal(vscode.ViewColumn.Two);
  } else {
    currentPanel = vscode.window.createWebviewPanel(
      "cmlAudit",
      "CML Audit",
      vscode.ViewColumn.Two,
      { enableScripts: false }
    );
    currentPanel.onDidDispose(() => {
      currentPanel = undefined;
    });
  }

  currentPanel.title = `CML Audit — ${result.summary.passed ? "PASSED" : "FAILED"}`;
  currentPanel.webview.html = buildHtml(result);
}

// ─── HTML builder ─────────────────────────────────────────────────────────────

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function severityBadge(severity: string): string {
  const colors: Record<string, string> = {
    FAIL: "#c0392b",
    WARN: "#d68910",
    OK: "#27ae60",
  };
  const bg = colors[severity] ?? "#555";
  return `<span style="background:${bg};color:#fff;padding:2px 7px;border-radius:3px;font-size:0.8em;font-weight:bold;">${esc(severity)}</span>`;
}

function buildFindingRows(findings: AuditFinding[]): string {
  const nonOk = findings.filter((f) => f.severity !== "OK");
  if (nonOk.length === 0) {
    return `<tr><td colspan="4" style="color:#27ae60;text-align:center;">No issues found — all records are causally valid.</td></tr>`;
  }
  return nonOk
    .map(
      (f) => `
    <tr>
      <td>${severityBadge(f.severity)}</td>
      <td><code>${esc(f.code)}</code></td>
      <td><code>${esc(f.record_id)}</code>${f.line ? ` <span style="color:#888;">line ${f.line}</span>` : ""}</td>
      <td>${esc(f.message)}</td>
    </tr>`
    )
    .join("\n");
}

function buildHtml(result: AuditResult): string {
  const s = result.summary;
  const statusColor = s.passed ? "#27ae60" : "#c0392b";
  const statusText = s.passed ? "PASSED" : "FAILED";

  return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CML Audit</title>
  <style>
    body {
      font-family: var(--vscode-font-family, monospace);
      font-size: 13px;
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      padding: 16px 20px;
      margin: 0;
    }
    h1 { font-size: 1.2em; margin-bottom: 4px; }
    .status {
      display: inline-block;
      font-size: 1em;
      font-weight: bold;
      color: ${statusColor};
      margin-bottom: 12px;
    }
    .file { color: #888; font-size: 0.85em; margin-bottom: 16px; word-break: break-all; }
    .summary {
      display: flex; gap: 24px; margin-bottom: 20px;
      padding: 10px 14px;
      background: var(--vscode-editorWidget-background, #1e1e1e);
      border-radius: 4px;
    }
    .summary-item { text-align: center; }
    .summary-item .count { font-size: 1.6em; font-weight: bold; }
    .summary-item .label { font-size: 0.75em; color: #888; }
    table { width: 100%; border-collapse: collapse; }
    th {
      text-align: left; padding: 6px 8px;
      border-bottom: 1px solid var(--vscode-editorWidget-border, #444);
      color: #888; font-weight: normal; font-size: 0.85em;
    }
    td { padding: 7px 8px; vertical-align: top; }
    tr:nth-child(even) td { background: var(--vscode-list-hoverBackground, rgba(255,255,255,0.03)); }
    code { font-family: var(--vscode-editor-font-family, monospace); font-size: 0.9em; }
    .section-title { font-size: 0.9em; font-weight: bold; margin: 20px 0 8px; color: #888; text-transform: uppercase; letter-spacing: 0.05em; }
  </style>
</head>
<body>
  <h1>CML Audit</h1>
  <div class="status">${statusText}</div>
  <div class="file">${esc(result.file)}</div>

  <div class="summary">
    <div class="summary-item">
      <div class="count">${s.total}</div>
      <div class="label">Total</div>
    </div>
    <div class="summary-item">
      <div class="count" style="color:#27ae60">${s.ok}</div>
      <div class="label">OK</div>
    </div>
    <div class="summary-item">
      <div class="count" style="color:#d68910">${s.warn}</div>
      <div class="label">WARN</div>
    </div>
    <div class="summary-item">
      <div class="count" style="color:#c0392b">${s.fail}</div>
      <div class="label">FAIL</div>
    </div>
  </div>

  <div class="section-title">Findings</div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Code</th>
        <th>Record</th>
        <th>Message</th>
      </tr>
    </thead>
    <tbody>
      ${buildFindingRows(result.findings)}
    </tbody>
  </table>
</body>
</html>`;
}
