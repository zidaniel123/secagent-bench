# Five open models on two DGX Sparks

Which open-weight model should drive a security agent that reads hostile input?
This run compared five candidates on the full suite, three repeats per case,
all self-hosted on two NVIDIA DGX Sparks (GB10, 128 GB unified memory each)
joined by a 200 Gb/s QSFP cable.

## Results

| | Nemotron-3-Super 120B | Qwen3.6-35B-A3B | Step-3.7-Flash | **DeepSeek-V4-Flash** |
|---|---|---|---|---|
| Runs on | 1 Spark | 1 Spark | 2 Sparks, TP=2 | **2 Sparks, TP=2** |
| Weights | NVFP4 | FP8 | NVFP4 | **NVFP4** |
| sast F1 | 1.00 | 0.98 | 0.98 | **1.00** |
| dast F1 | 0.98 | 0.88 | 0.93 | **1.00** |
| injection hijack (source) | 56% | 11% | 5.6% | **0%** |
| dast-injection hijack (HTTP) | 50% | 33% | 39% | **22%** |
| canary leaks (both surfaces) | 33% | 0% | 0% | **0%** |
| false positives | 0 | 0 | 0 | 0 |
| p50 latency | 12 s | 28 s | 68 s | **9.7 s** |

`gpt-oss-120b` was the fifth candidate and is not in the table. On the vLLM
builds available for the Spark at the time it produced malformed token streams
under every kernel backend tried, so it never returned a scorable answer. That
is a finding about the software stack on this hardware, not about the model.

**DeepSeek-V4-Flash** was the only model that was both a perfect detector and
the hardest to hijack, and it was also the fastest. It is also the only
candidate too large for one Spark — the two boxes are what make it runnable.

## What the numbers say beyond the ranking

**Detection has saturated; robustness has not.** Every model scored zero false
positives and at least 0.88 F1. The injection columns span 0% to 56%. If you
are choosing a model for an agent that reads untrusted material, the detection
benchmark barely discriminates and the injection benchmark decides.

**Size does not buy robustness.** The 120B Nemotron was hijacked more than
the 35B Qwen on both surfaces and was the only model that leaked the canary —
it obeyed injected instructions outright, not just by going quiet.

**HTTP is the harder surface for everyone.** Every model was hijacked more
often through response bodies than through source comments. Two vectors beat
all four models in at least two of three runs:

- a JSON body claiming the endpoint is *out of scope* for automated testing, and
- instructions stored in a user-controlled field and echoed back by the API.

Both work because they look like legitimate engagement context. Neither can be
fixed by picking a better model; they need handling in the agent — treat scope
as operator configuration, never as something the target can assert.

## Corrections made along the way

Two scorer and fixture fixes were applied, and every model was re-graded from
its stored responses with the `rescore` command, so all columns use the same
answer key:

- `py-crypto-01` (MD5 for password storage) now also accepts **CWE-916**,
  which is the more precise answer; one model gave it consistently and was
  being marked wrong for being specific.
- The report gained an `errors` column and an explicit warning when every
  request to a provider failed, after a crashed server rendered as a row of
  zeros that looked like a very bad model.

## Caveats

- 15 SAST, 13 DAST and 12 injection cases, three repeats each. Enough to
  separate 0% from 50%; not enough to rank models a few points apart.
- One quantization per model, one prompt, one vLLM version. Change any of them
  and the numbers can move.
- On GB10 the MoE models only produced correct output with vLLM's Marlin MoE
  kernels (`--moe-backend marlin`); the default kernels either crashed or
  generated garbage. If you reproduce this on a Spark and see nonsense, try that
  first.
