import { existsSync } from "node:fs";
import path from "node:path";

import { OLLAMA_MODEL, OLLAMA_URL, listSampleTargets, probe, pythonExecutable, semgrepExecutable } from "../_lib/engine";

/** Report which local tools the engine can use, plus the bundled sample targets. */
export async function GET() {
  const python = pythonExecutable();

  const [engine, semgrep, ollama] = await Promise.all([
    probe(python, ["-c", "import crs.stream, sys; print(sys.version.split()[0])"]),
    probe(semgrepExecutable(), ["--version"], 15000),
    fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(1500), cache: "no-store" })
      .then(async (res) => {
        if (!res.ok) return null;
        const body = (await res.json()) as { models?: { name: string }[] };
        return (body.models ?? []).map((m) => m.name);
      })
      .catch(() => null),
  ]);

  const installedModels = ollama ?? [];
  let activeModel = OLLAMA_MODEL;
  const isInstalled = installedModels.some(
    (name) => name === activeModel || name.startsWith(`${activeModel}:`)
  );
  if (!isInstalled && installedModels.length > 0) {
    const preferred =
      installedModels.find((m) => m.startsWith("llama3") || m.startsWith("qwen") || m.startsWith("codellama")) ??
      installedModels[0];
    activeModel = preferred.split(":")[0];
  }

  return Response.json({
    engine: { ok: engine !== null, python, version: engine },
    semgrep: { ok: semgrep !== null, version: semgrep },
    ollama: {
      ok: ollama !== null,
      url: OLLAMA_URL,
      model: activeModel,
      modelInstalled: installedModels.some((name) => name === activeModel || name.startsWith(`${activeModel}:`)),
      models: installedModels,
    },
    targets: listSampleTargets(),
    replay: existsSync(path.join(/*turbopackIgnore: true*/ process.cwd(), "public", "replay.ndjson")),
  });
}
