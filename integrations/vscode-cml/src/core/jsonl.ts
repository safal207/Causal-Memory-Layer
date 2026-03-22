/**
 * Utilities for working with JSONL causal log files in the editor.
 */

import * as vscode from "vscode";

/** Parse each non-empty line as JSON, return a map from record id → 0-based line index. */
export function buildIdToLineMap(document: vscode.TextDocument): Map<string, number> {
  const map = new Map<string, number>();
  for (let i = 0; i < document.lineCount; i++) {
    const text = document.lineAt(i).text.trim();
    if (!text) {
      continue;
    }
    try {
      const rec = JSON.parse(text) as { id?: string };
      if (rec.id) {
        map.set(rec.id, i);
      }
    } catch {
      // Skip malformed lines
    }
  }
  return map;
}

/**
 * Return the record id for the JSON object on the cursor's current line.
 * Returns undefined if the line is not valid JSON or has no `id` field.
 */
export function recordIdAtCursor(editor: vscode.TextEditor): string | undefined {
  const line = editor.document.lineAt(editor.selection.active.line);
  const text = line.text.trim();
  if (!text) {
    return undefined;
  }
  try {
    const rec = JSON.parse(text) as { id?: string };
    return rec.id;
  } catch {
    return undefined;
  }
}
