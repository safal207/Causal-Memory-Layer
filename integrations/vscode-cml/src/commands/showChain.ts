/**
 * Command: CML: Show Chain for Selected Record
 *
 * Reads the record id from the line under the cursor, runs chain
 * reconstruction via the CLI, and displays the result in an output channel.
 */

import * as vscode from "vscode";
import { runChain, ChainRecord } from "../core/cli";
import { recordIdAtCursor } from "../core/jsonl";

let chainChannel: vscode.OutputChannel | undefined;

function getChainChannel(): vscode.OutputChannel {
  if (!chainChannel) {
    chainChannel = vscode.window.createOutputChannel("CML Chain");
  }
  return chainChannel;
}

function formatRecord(rec: ChainRecord, index: number, total: number): string {
  const step = `[${index + 1}/${total}]`;
  const obj =
    typeof rec.object === "object" && rec.object !== null
      ? JSON.stringify(rec.object)
      : String(rec.object);
  const actor = rec.actor
    ? `pid=${rec.actor.pid}${rec.actor.comm ? ` (${rec.actor.comm})` : ""}`
    : "?";
  const parent = rec.parent_cause ?? "null";
  return [
    `${step} id=${rec.id}`,
    `    action      : ${rec.action}`,
    `    object      : ${obj}`,
    `    actor       : ${actor}`,
    `    permitted_by: ${rec.permitted_by}`,
    `    parent_cause: ${parent}`,
    rec.time_iso ? `    time        : ${rec.time_iso}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

export async function showChainForSelectedRecord(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage("CML: No active editor.");
    return;
  }

  const recordId = recordIdAtCursor(editor);
  if (!recordId) {
    vscode.window.showErrorMessage(
      'CML: Could not find a record with an "id" field on the current line.'
    );
    return;
  }

  const filePath = editor.document.uri.fsPath;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `CML: Reconstructing chain for '${recordId}'…`,
      cancellable: false,
    },
    async () => {
      try {
        const result = await runChain(filePath, recordId);
        const ch = getChainChannel();
        ch.clear();
        ch.show(true);

        ch.appendLine("═".repeat(60));
        ch.appendLine(`CML Chain — target: ${result.target_id}`);
        ch.appendLine("═".repeat(60));
        ch.appendLine("");

        if (result.chain.length === 0) {
          ch.appendLine("  (no chain records found)");
        } else {
          result.chain.forEach((rec, i) => {
            ch.appendLine(formatRecord(rec, i, result.chain.length));
            if (i < result.chain.length - 1) {
              ch.appendLine("          │");
              ch.appendLine("          ▼");
            }
          });
        }

        if (result.has_gap && result.gap_note) {
          ch.appendLine("");
          ch.appendLine("─".repeat(60));
          ch.appendLine(`⚠  GAP: ${result.gap_note}`);
        }

        if (result.r3_context) {
          ch.appendLine("");
          ch.appendLine("─".repeat(60));
          ch.appendLine("✗  R3 VIOLATION: SECRET access not in causal chain");
          ch.appendLine(`   ${result.r3_context.note}`);
          ch.appendLine("");
          ch.appendLine("   Unlinked SECRET record:");
          const sr = result.r3_context.secret_record;
          const srObj =
            typeof sr.object === "object" && sr.object !== null
              ? JSON.stringify(sr.object)
              : String(sr.object);
          ch.appendLine(`     id     : ${sr.id}`);
          ch.appendLine(`     action : ${sr.action}`);
          ch.appendLine(`     object : ${srObj}`);
          ch.appendLine(`     actor  : pid=${sr.actor?.pid}`);
        }

        ch.appendLine("");
        ch.appendLine("═".repeat(60));
      } catch (err) {
        vscode.window.showErrorMessage(`CML Chain error: ${String(err)}`);
      }
    }
  );
}
