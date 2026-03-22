/**
 * Maps CML audit findings to VS Code diagnostics (Problems panel).
 *
 * FAIL findings → Error diagnostics
 * WARN findings → Warning diagnostics
 */

import * as vscode from "vscode";
import { AuditFinding, AuditResult } from "./cli";

let diagnosticCollection: vscode.DiagnosticCollection | undefined;

export function getDiagnosticCollection(): vscode.DiagnosticCollection {
  if (!diagnosticCollection) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection("cml");
  }
  return diagnosticCollection;
}

/** Apply audit findings as VS Code diagnostics on the given document. */
export function applyDiagnostics(
  document: vscode.TextDocument,
  result: AuditResult,
  idToLine: Map<string, number>
): void {
  const collection = getDiagnosticCollection();
  const diagnostics: vscode.Diagnostic[] = [];

  for (const finding of result.findings) {
    if (finding.severity === "OK") {
      continue;
    }

    // Resolve line number: prefer the finding's own line, fall back to id map
    let lineIndex: number | undefined;
    if (finding.line !== null && finding.line !== undefined) {
      lineIndex = finding.line - 1; // convert 1-based → 0-based
    } else {
      lineIndex = idToLine.get(finding.record_id);
    }

    // Clamp to document bounds
    if (lineIndex === undefined || lineIndex < 0) {
      lineIndex = 0;
    }
    if (lineIndex >= document.lineCount) {
      lineIndex = document.lineCount - 1;
    }

    const lineText = document.lineAt(lineIndex).text;
    const range = new vscode.Range(
      lineIndex,
      0,
      lineIndex,
      lineText.length
    );

    const severity =
      finding.severity === "FAIL"
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;

    const diag = new vscode.Diagnostic(range, finding.message, severity);
    diag.source = "CML";
    diag.code = finding.code;

    diagnostics.push(diag);
  }

  collection.set(document.uri, diagnostics);
}

/** Clear all CML diagnostics. */
export function clearDiagnostics(): void {
  getDiagnosticCollection().clear();
}
