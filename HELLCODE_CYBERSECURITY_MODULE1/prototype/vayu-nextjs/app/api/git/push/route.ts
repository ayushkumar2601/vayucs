import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { REPO_ROOT } from "../../_lib/engine";

const execFileAsync = promisify(execFile);

async function runGit(args: string[], cwd: string): Promise<{ stdout: string; stderr: string }> {
  return await execFileAsync("git", args, {
    cwd,
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
  });
}

/**
 * Push repository code directly to GitHub.
 *
 * Checks for uncommitted changes, creates a verified CRS remediation commit
 * if necessary, and executes `git push origin <branch>`.
 */
export async function POST(request: Request) {
  try {
    let body: { message?: string; branch?: string } = {};
    try {
      body = await request.json();
    } catch {
      // Empty or non-JSON body is acceptable; use defaults
    }

    // 1. Verify working tree
    await runGit(["rev-parse", "--is-inside-work-tree"], REPO_ROOT);

    // 2. Identify current branch
    let branch = "main";
    try {
      const branchRes = await runGit(["branch", "--show-current"], REPO_ROOT);
      if (branchRes.stdout.trim()) {
        branch = branchRes.stdout.trim();
      }
    } catch {
      // Fall back to main
    }

    // If request specified a branch, use it if allowed
    if (body.branch && typeof body.branch === "string" && !body.branch.includes(" ")) {
      branch = body.branch;
    }

    // 3. Inspect git status
    const statusRes = await runGit(["status", "--porcelain"], REPO_ROOT);
    const hasChanges = statusRes.stdout.trim().length > 0;
    let committed = false;

    if (hasChanges) {
      // Stage all changes
      await runGit(["add", "-A"], REPO_ROOT);

      const commitMessage =
        body.message?.trim() ||
        "fix(security): apply VAYU verified remediation and cloud sandbox updates";

      try {
        await runGit(["commit", "-m", commitMessage], REPO_ROOT);
        committed = true;
      } catch (commitErr: any) {
        // If nothing to commit (e.g. whitespace only), continue to push
        if (!commitErr.stdout?.includes("nothing to commit")) {
          throw commitErr;
        }
      }
    }

    // 4. Push to remote origin
    const pushRes = await runGit(["push", "origin", branch], REPO_ROOT);

    // 5. Query latest commit SHA and remote URL
    const shaRes = await runGit(["rev-parse", "--short", "HEAD"], REPO_ROOT);
    const shortSha = shaRes.stdout.trim();

    let remoteUrl = "https://github.com/ayushkumar2601/vayu_hacktoberfest";
    try {
      const remoteRes = await runGit(["remote", "get-url", "origin"], REPO_ROOT);
      remoteUrl = remoteRes.stdout.trim();
    } catch {
      // Ignore
    }

    return Response.json({
      success: true,
      message: committed
        ? `Successfully committed (${shortSha}) and pushed to GitHub (${branch})`
        : `Successfully pushed branch ${branch} to GitHub (${shortSha})`,
      branch,
      commitSha: shortSha,
      remoteUrl,
      committed,
      output: pushRes.stderr || pushRes.stdout,
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    const stderr = err?.stderr || "";
    const stdout = err?.stdout || "";
    const errorMsg = err?.message || "Git push failed";

    return Response.json(
      {
        success: false,
        error: errorMsg,
        stderr: stderr.trim(),
        stdout: stdout.trim(),
      },
      { status: 500 },
    );
  }
}
