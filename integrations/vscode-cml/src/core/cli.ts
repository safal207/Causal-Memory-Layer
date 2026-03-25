/**
 * Thin wrapper around the CML Python CLI.
 *
 * Preferred invocation order:
 *   1. python3 -m cli.main  (repo-local, from workspace root)
 *   2. python  -m cli.main  (repo-local, from workspace root)
 *
 * The workspace root is inferred from the first open workspace folder.
 */

import * as cp from "child_process";
import * as path from "path";
import * as vscode from "vscode";

export interface AuditSummary {
  total: number;
  ok: number;
  warn: number;
  fail: number;
  passed: boolean;
}

export interface AuditFinding {
  rule: string;
  code: string;
  severity: "OK" | "WARN" | "FAIL";
  record_id: string;
  line: number | null;
  message: string;
}

export interface AuditResult {
  file: string;
  summary: AuditSummary;
  findings: AuditFinding[];
}

export interface ChainRecord {
  id: string;
  action: string;
  object: unknown;
  actor: { pid: number; ppid?: number; uid?: number; comm?: string };
  permitted_by: string;
  parent_cause: string | null;
  timestamp?: number;
  time_iso?: string;
}

export interface ChainResult {
  target_id: string;
  chain: ChainRecord[];
  has_gap: boolean;
  gap_note: string | null;
  r3_context: {
    secret_record: ChainRecord;
    note: string;
  } | null;
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function repoRoot(): string {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    throw new Error("No workspace folder is open. Please open the Causal-Memory-Layer repository.");
  }
  return folders[0].uri.fsPath;
}

/**
 * Spawn a child process trying each python candidate in turn.
 * Returns stdout as a string on success, throws on failure.
 */
function spawnCml(args: string[], cwd: string): Promise<string> {
  const candidates = ["python3", "python"];

  return new Promise((resolve, reject) => {
    function tryNext(remaining: string[]) {
      if (remaining.length === 0) {
        reject(
          new Error(
            "CML CLI not found.\n\n" +
              "Make sure Python (python3 or python) is in PATH and you have the " +
              "Causal-Memory-Layer repository open as your workspace."
          )
        );
        return;
      }

      const py = remaining[0];
      const proc = cp.spawn(py, ["-m", "cli.main", ...args], {
        cwd,
        env: process.env,
      });

      let stdout = "";
      let stderr = "";
      proc.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
      proc.stderr.on("data", (d: Buffer) => (stderr += d.toString()));

      proc.on("close", (code) => {
        if (code === 0) {
          resolve(stdout);
        } else if (remaining.length > 1) {
          // Try the next candidate
          tryNext(remaining.slice(1));
        } else {
          reject(new Error(`CML CLI exited with code ${code}:\n${stderr || stdout}`));
        }
      });

      proc.on("error", () => {
        // Binary not found — try next candidate
        tryNext(remaining.slice(1));
      });
    }

    tryNext(candidates);
  });
}

// ─── public API ───────────────────────────────────────────────────────────────

export async function runAudit(filePath: string): Promise<AuditResult> {
  const cwd = repoRoot();
  // Use absolute path so the CLI works regardless of cwd
  const absFile = path.isAbsolute(filePath)
    ? filePath
    : path.join(cwd, filePath);

  const stdout = await spawnCml(["audit", absFile, "--format", "json"], cwd);
  try {
    return JSON.parse(stdout) as AuditResult;
  } catch {
    throw new Error(`CML audit returned invalid JSON:\n${stdout}`);
  }
}

export async function runChain(
  filePath: string,
  recordId: string
): Promise<ChainResult> {
  const cwd = repoRoot();
  const absFile = path.isAbsolute(filePath)
    ? filePath
    : path.join(cwd, filePath);

  const stdout = await spawnCml(["chain", absFile, recordId], cwd);
  try {
    return JSON.parse(stdout) as ChainResult;
  } catch {
    throw new Error(`CML chain returned invalid JSON:\n${stdout}`);
  }
}
