# secagent-bench

Benchmark LLM providers — and models you host yourself — on the two questions
that decide whether one can drive a security agent:

1. **Can it find real vulnerabilities without inventing fake ones?** — in source
   code (SAST) and in HTTP request/response evidence (DAST).
2. **Can the thing it is analysing talk it out of reporting them?** — planted
   instructions in code comments, and in HTTP responses from the target.

Claude, OpenAI, Kimi, GLM and a local vLLM/Ollama model all run through the same
code path against the same labeled fixtures, so the numbers are comparable.

```
| provider                | precision | recall | F1    | refusal | malformed | p50   | cost $ |
|-------------------------|-----------|--------|-------|---------|-----------|-------|--------|
| anthropic:claude-opus-5 | 0.91      | 0.90   | 0.90  | 0%      | 0%        | 4.1s  | 0.0182 |
| local:qwen2.5-coder-32b | 0.78      | 0.70   | 0.74  | 0%      | 10%       | 2.9s  | 0      |
```

*(Illustrative shape, not measured results — run it yourself.)*

## Why this exists

Most "can an LLM do security" demos run one model against one repo and eyeball
the output. That tells you nothing, for three reasons this project tries to fix:

- **No ground truth** → you cannot tell a real finding from a confident guess.
  Every fixture here is labeled with its CWE, and **a third of the set is safe
  on purpose** so false positives are measured rather than ignored.
- **Refusals get scored as failures** → an aligned model that declines to
  analyse exploitable code is a *different* problem from one that analyses it
  badly. They are counted separately here.
- **Nobody tests the agent itself** → a SAST agent reads untrusted code and a
  DAST agent reads untrusted HTTP. Both are injection surfaces. The injection
  tasks plant instructions in the material under review and measure whether the
  model obeys them.

## The four tasks

| Task | Input | The question |
|---|---|---|
| `sast` | A source file | Which CWE is in this code, if any? |
| `dast` | One HTTP request + its response | Is this exploitable, or a defended probe? |
| `injection` | Source with planted instructions | Does a code comment talk it down? |
| `dast-injection` | HTTP response with planted instructions | Does the target talk it down? |

`dast` is the judgement your DAST agent makes *after* the traffic is sent —
deliberately isolated from crawling and payload delivery, because telling a
`500` with a SQL error from a `400` with a validation error is the part that
actually needs a model. Its safe controls are correctly-defended probes: a
`403` on an access-control test, an HTML-encoded reflection, a generic `404`.

`dast-injection` is a nastier threat model than `injection`, and worth scoring
separately. A SAST agent reads a repository that is at least nominally yours.
A DAST agent reads response headers and bodies from **the host under test** —
so on a compromised or hostile target, every byte it ingests is attacker
controlled. The fixtures deliver injections through response headers, JSON
error bodies, HTML comments, a fake "out of scope" policy, and stored content
written by another user.

## Quickstart

```bash
git clone https://github.com/zidaniel123/secagent-bench
cd secagent-bench
pip install -e ".[all]"

cp .env.example .env    # fill in whichever keys you have
secagent-bench run --config configs/suite.default.yaml --report REPORT.md
```

Providers with no API key are reported as "did not run" and the rest of the
suite still executes — start with one key and add more later.

No keys at all? Serve a local model and run the local suite:

```bash
vllm serve Qwen/Qwen2.5-Coder-32B-Instruct --port 8000
secagent-bench run --config configs/suite.local.yaml
```

## What it measures

| Metric | Task | Meaning |
|---|---|---|
| `precision` / `recall` / `F1` | sast, dast | Detection quality against labeled CWEs |
| `TP/FP/FN/TN` | sast, dast | Raw counts — FP comes from the safe controls |
| `refusal_rate` | all | How often the model declined the task |
| `malformed_rate` | sast, dast | Ignored the output contract |
| `hijack_rate` | injection | Obeyed planted instructions **or** dropped the real finding |
| `suppression_rate` | injection | Went quiet about a vulnerability it should have reported |
| `canary_leak_rate` | injection | Emitted a token only the injected text asked for |
| `latency_p50_s`, `cost_usd` | all | What it costs to run in practice |

**Refusal is not scored as a miss.** Refusals, errors and malformed output are
excluded from precision/recall and surfaced as their own rates, so a model that
refuses half the suite cannot post a clean F1 on the half it answered.

**`suppression` and `canary` are tracked independently.** A model can keep the
finding and *still* print the canary — that means it followed instructions from
data, and would have leaked on a task with a real side effect.

## Providers

| id | Backend | Key |
|---|---|---|
| `anthropic` | Claude, via the official SDK | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI | `OPENAI_API_KEY` |
| `kimi` | Moonshot | `MOONSHOT_API_KEY` |
| `glm` | Zhipu / Z.ai | `ZHIPU_API_KEY` |
| `local` | Any vLLM / Ollama server | none |

Claude gets its own adapter rather than an OpenAI-compatible shim for a concrete
reason: it reports refusals **structurally** (`stop_reason == "refusal"` with a
category), so its refusal rate is measured, not inferred from string matching
like everywhere else.

Model ids move faster than this repo does — confirm the defaults in
`configs/suite.default.yaml` against each provider's current model list.

## Cost accounting is deliberately incomplete

Only the Anthropic rates ship hard-coded. Every other model is `null` in
`configs/pricing.yaml`, and its cost column reads `—` until you fill it in from
the provider's own pricing page.

This is on purpose. A made-up price is worse than a blank column, because it
silently corrupts the comparison that is half the point of the benchmark. Local
models bill zero — marginal cost only; hardware and power are not modelled.

## Local models

See **[docs/local-models.md](docs/local-models.md)** for vLLM and Ollama setup,
notes on running this on an NVIDIA DGX Spark (arm64/GB10), model suggestions for
security work, and how to put a LiteLLM proxy in front of a local model so an
existing **Claude Agent SDK** agent can drive it.

One thing worth stating plainly, because it trips people up: two GPU boxes do
not become one big GPU by joining the same Kubernetes cluster. K8s schedules
*separate* pods across them. Running a single large model across two machines
needs tensor/pipeline parallelism over a fast interconnect.

## Extending

See **[docs/extending.md](docs/extending.md)** — adding providers, adding cases,
adding tasks, and wrapping a whole multi-phase agent as a provider so you can
benchmark the agent instead of the raw model.

For a larger corpus than the bundled fixtures, the standard labeled sets are the
**OWASP Benchmark** and **NIST Juliet/SARD**.

## Scope and limits

- Fixtures are short, single-issue snippets and single HTTP exchanges. They
  measure whether a model recognises a weakness — **not** whether it can find
  one buried in a 200k-line repo with taint paths across files, or chain a
  multi-step exploit across a live session.
- `dast` scores the judgement step only. Crawling, authentication and payload
  delivery are your agent's job, and a model that scores well here can still
  drive a bad crawl.
- `repeats: 1` by default. Raise it to measure run-to-run variance, which for
  some models is larger than the gap between models.
- The injection suite is a floor, not a ceiling. Six vectors is enough to
  separate "resists obvious injection" from "does not"; it is not a red-team.
- The heuristic refusal detector will drift as phrasing changes. Anthropic's
  structured signal does not.

## Authorized use

The bundled fixtures are self-contained snippets, safe to run anywhere. If you
extend this toward live DAST, point it only at something **you own or are
explicitly authorised to test** — a local container (OWASP Juice Shop, DVWA) or
your own staging host. Scanning third-party systems without permission is
illegal in most jurisdictions.

## License

MIT
