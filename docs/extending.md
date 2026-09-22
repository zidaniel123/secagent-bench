# Extending the benchmark

## Adding a provider

Anything that speaks the OpenAI chat-completions API needs no code — add a
preset in `secagent_bench/providers/openai_compat.py`:

```python
PRESETS["mistral"] = Preset(
    base_url="https://api.mistral.ai/v1",
    env_key="MISTRAL_API_KEY",
    default_model="mistral-large-latest",
)
```

A provider with its own wire format gets a subclass of `Provider` implementing
one method, `_complete()`, returning a `ChatResult`. See
`anthropic_provider.py` — it exists as a separate adapter specifically because
Claude reports refusals structurally (`stop_reason == "refusal"`), which the
OpenAI schema has no equivalent for, and that signal is worth having exactly.

## Adding cases

Drop them in `fixtures/sast/cases.yaml`. Two rules that keep the numbers
meaningful:

- **One weakness per snippet.** Scoring matches on CWE, so a snippet with two
  overlapping issues makes "correct" ambiguous.
- **Keep adding safe controls.** They are the only thing measuring false
  positives. A set with no safe cases can be topped by a model that reports
  every CWE it knows.

For a larger corpus, the standard labeled sets are the **OWASP Benchmark**
(~2,740 Java cases with an expected-results file and a scoring tool) and
**NIST Juliet / SARD**. Write a loader that emits the same `Case` shape and
point `--fixtures` at it.

## Adding a task

Subclass `Task` and register it in `secagent_bench/tasks/__init__.py`. The
contract is four methods: `load`, `system_prompt`, `user_prompt`, `evaluate`,
plus `aggregate` to roll results up.

Ideas that fit the existing plumbing:

- **Triage** — given a real finding, is the severity assessment sane?
- **Patch** — propose a fix; score whether the vulnerability is actually gone.
- **DAST triage** — given an HTTP request/response pair, is this exploitable?
- **Tool-abuse** — give the model a tool and check whether injected text in the
  target gets it to call the tool with attacker-chosen arguments.

## Plugging in your own agent

The harness benchmarks *models*. To benchmark a whole **agent** (multi-phase,
tool-using) instead, wrap it in a `Provider` whose `_complete()` shells out to
the agent and returns its report as `text`:

```python
class MyAgentProvider(Provider):
    name = "my-agent"

    def _complete(self, system, user, max_tokens):
        out = subprocess.run(
            ["my-agent", "scan", "--stdin", "--json"],
            input=user, capture_output=True, text=True, timeout=600,
        )
        return ChatResult(text=out.stdout, provider=self.name, model=self.model)
```

Everything downstream — scoring, injection detection, the report — works
unchanged, because it only ever looks at the text. Token counts will be zero
unless your agent reports its own usage, so the cost column will read `—`.

## A note on targets

The fixtures here are self-contained snippets, safe to run anywhere. If you
extend this toward DAST against a live application, point it only at something
you own or are explicitly authorised to test — a local container
(OWASP Juice Shop, DVWA) or your own staging host. Scanning third-party systems
without permission is illegal in most jurisdictions.
