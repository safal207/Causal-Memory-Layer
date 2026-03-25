/**
 * Command: CML: Audit Example Log
 *
 * Shows a quick pick with the bundled example logs so users can
 * quickly try the extension against known-good and known-bad inputs.
 */

import * as vscode from "vscode";
import * as path from "path";
import { runAudit } from "../core/cli";
import { buildIdToLineMap } from "../core/jsonl";
import { applyDiagnostics } from "../core/diagnostics";
import { showAuditPanel } from "../views/auditPanel";

const EXAMPLES = [
  {
    label: "secret_to_net_log.jsonl",
    description: "Demonstrates R3: SECRET → NET_OUT without causal link (has FAIL)",
    relativePath: path.join("examples", "secret_to_net_log.jsonl"),
  },
  {
    label: "exec_causal_log.jsonl",
    description: "Simple parent-child exec chain — all rules pass",
    relativePath: path.join("examples", "exec_causal_log.jsonl"),
  },
];

export async function auditExampleLog(
  context: vscode.ExtensionContext
): Promise<void> {
  const picked = await vscode.window.showQuickPick(EXAMPLES, {
    placeHolder: "Select an example causal log to audit",
    matchOnDescription: true,
  });

  if (!picked) {
    return;
  }

  // Resolve against workspace root
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showErrorMessage(
      "CML: No workspace folder open. Please open the Causal-Memory-Layer repository."
    );
    return;
  }
  const filePath = path.join(folders[0].uri.fsPath, picked.relativePath);

  // Open the file in the editor first so the user can see it
  let document: vscode.TextDocument;
  try {
    document = await vscode.workspace.openTextDocument(filePath);
    await vscode.window.showTextDocument(document, vscode.ViewColumn.One);
  } catch {
    vscode.window.showErrorMessage(
      `CML: Could not open example file:\n${filePath}\n\n` +
        "Make sure the Causal-Memory-Layer repository is your open workspace."
    );
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `CML: Auditing ${picked.label}…`,
      cancellable: false,
    },
    async () => {
      try {
        const result = await runAudit(filePath);
        const idToLine = buildIdToLineMap(document);

        applyDiagnostics(document, result, idToLine);
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
