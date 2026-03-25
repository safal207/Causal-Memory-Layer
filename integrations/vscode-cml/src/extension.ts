/**
 * CML VS Code Extension — entry point.
 *
 * Registers the three core commands and the diagnostic collection.
 * All heavy lifting is delegated to the existing Python CLI.
 */

import * as vscode from "vscode";
import { auditCurrentLog } from "./commands/auditCurrentLog";
import { showChainForSelectedRecord } from "./commands/showChain";
import { auditExampleLog } from "./commands/auditExample";
import { getDiagnosticCollection } from "./core/diagnostics";

export function activate(context: vscode.ExtensionContext): void {
  // Register diagnostic collection so VS Code cleans it up on deactivation
  context.subscriptions.push(getDiagnosticCollection());

  context.subscriptions.push(
    vscode.commands.registerCommand("cml.auditCurrentLog", () =>
      auditCurrentLog(context)
    ),
    vscode.commands.registerCommand("cml.showChainForSelectedRecord", () =>
      showChainForSelectedRecord()
    ),
    vscode.commands.registerCommand("cml.auditExampleLog", () =>
      auditExampleLog(context)
    )
  );
}

export function deactivate(): void {
  // VS Code disposes subscriptions automatically
}
