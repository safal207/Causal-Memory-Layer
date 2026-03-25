/**
 * Command: CML: Audit Current Log
 *
 * Runs the CML audit against the file open in the active editor,
 * shows a summary panel, and attaches diagnostics to the editor.
 */

import * as vscode from "vscode";
import { runAudit } from "../core/cli";
import { buildIdToLineMap } from "../core/jsonl";
import { applyDiagnostics } from "../core/diagnostics";
import { showAuditPanel } from "../views/auditPanel";

export async function auditCurrentLog(
  context: vscode.ExtensionContext
): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage("CML: No active editor.");
    return;
  }

  const filePath = editor.document.uri.fsPath;
  if (!filePath.endsWith(".jsonl")) {
    vscode.window.showWarningMessage(
      "CML: Active file does not appear to be a .jsonl causal log."
    );
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "CML: Running audit…",
      cancellable: false,
    },
    async () => {
      try {
        const result = await runAudit(filePath);
        const idToLine = buildIdToLineMap(editor.document);

        applyDiagnostics(editor.document, result, idToLine);
        showAuditPanel(context, result);

        const { summary: s } = result;
        const msg = s.passed
          ? `CML Audit passed — ${s.ok} OK, ${s.warn} WARN`
          : `CML Audit FAILED — ${s.fail} FAIL, ${s.warn} WARN`;

        if (s.passed) {
          vscode.window.showInformationMessage(msg);
        } else {
          vscode.window.showWarningMessage(msg);
        }
      } catch (err) {
        vscode.window.showErrorMessage(`CML Audit error: ${String(err)}`);
      }
    }
  );
}
