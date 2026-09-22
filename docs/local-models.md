# Running local models

The point of this harness is that a model on your own GPU is a first-class
column in the comparison, not a footnote. This page gets one serving so
`secagent-bench` can talk to it.

## Why bother, when the hosted APIs are right there

Three reasons specific to security work:

1. **No refusal tax.** Hosted models sometimes decline to analyse exploitable
   code or attack payloads. A security agent that gets refused is broken, and
   `refusal_rate` in the report exists to measure exactly this.
2. **Nothing leaves your network.** Scanning a client's code or your own
   production repo through a third-party API is often not allowed.
3. **Marginal cost is zero.** Once the hardware is running, a 5,000-case sweep
   costs electricity instead of an invoice.

## vLLM (recommended)

vLLM gives you an OpenAI-compatible server, which is all this harness needs.

```bash
pip install vllm

vllm serve Qwen/Qwen2.5-Coder-32B-Instruct \
  --host 0.0.0.0 --port 8000 \
  --max-model-len 16384
```

Point the suite at it:

```yaml
- id: local
  model: Qwen/Qwen2.5-Coder-32B-Instruct
  base_url: http://localhost:8000/v1
```

If the server is on another machine on your LAN, use its address — for example
`http://192.168.10.105:8000/v1`. Nothing else changes.

### On an NVIDIA DGX Spark (GB10, arm64)

The Sparks are `aarch64`, so use NVIDIA's arm64 PyTorch/vLLM builds rather than
the default x86 wheels. Each box has roughly 128 GB of unified memory, which
comfortably holds a 32B model at 8-bit or a 70B at 4-bit.

Two Sparks do **not** become one big GPU by being on the same network, or by
joining the same Kubernetes cluster. To run a single model across both, connect
them over the dedicated **ConnectX-7** link and serve with tensor or pipeline
parallelism (vLLM + Ray). Over ordinary 1 GbE ethernet, cross-node inference is
bottlenecked badly enough to not be worth it.

## Ollama

Simpler to start, slower under load, and quantised by default:

```bash
ollama serve
ollama pull qwen2.5-coder:32b
```

```yaml
- id: local
  model: qwen2.5-coder:32b
  base_url: http://localhost:11434/v1
```

## Models worth putting in the matrix

| Model | Why it earns a column |
|---|---|
| `Qwen2.5-Coder-32B-Instruct` | Strong code reasoning, fits one 128 GB box comfortably |
| `WhiteRabbitNeo` (various sizes) | Fine-tuned for offensive/defensive security; the clean test of whether removing refusals costs capability |
| `Llama-3.3-70B-Instruct` | General-purpose baseline at 4-bit |
| `DeepSeek-Coder-V2` | Taint-style reasoning over longer files |

Pair at least one uncensored and one aligned model. The interesting result is
usually not which finds more bugs — it is the gap between `refusal_rate` and
`hijack_rate`, because the same lack of guardrails that stops a model refusing
also tends to stop it resisting injected instructions.

## Driving an Anthropic-SDK agent with a local model

Tools built on the **Claude Agent SDK** speak the Anthropic API, not the OpenAI
one, so they cannot point straight at vLLM. Put a translating proxy in front:

```bash
pip install 'litellm[proxy]'

cat > litellm.yaml <<'YAML'
model_list:
  - model_name: local-analyst
    litellm_params:
      model: hosted_vllm/Qwen/Qwen2.5-Coder-32B-Instruct
      api_base: http://localhost:8000/v1
YAML

litellm --config litellm.yaml --port 4000
```

Then run the agent against the proxy:

```bash
export ANTHROPIC_BASE_URL=http://localhost:4000
export ANTHROPIC_API_KEY=anything
```

This harness does not need the proxy — it talks to vLLM directly. The proxy is
only for pointing an existing Anthropic-SDK agent at local weights.

## Sanity check

```bash
curl -s http://localhost:8000/v1/models | python3 -m json.tool
secagent-bench run --tasks sast --config configs/suite.local.yaml
```

If the first command lists your model and the second produces a table with a
non-zero `scored` count, the loop works.
