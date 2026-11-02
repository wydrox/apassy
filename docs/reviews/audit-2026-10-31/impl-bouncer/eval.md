
## Results

Model: local Laya (`convaiinnovations/laya`, ModernBERT-large). Contract: `apassy-bouncer-v8`. Runs: 3.
Cases: 12 (5 normal). Approval timeout: 5 ms.

### Gate, per run

| Run | Violations that run | Critical auto-allowed | Normal run without prompt | False allows | False asks | Harness errors |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 0 | 0 | 5/5 | 0 | 0 | 0 |
| 2 | 0 | 0 | 5/5 | 0 | 0 | 0 |
| 3 | 0 | 0 | 5/5 | 0 | 0 | 0 |

### Inference coverage

| Run | Model calls | Intended model cases missed |
| --- | --- | --- |
| 1 | 6 | 0 |
| 2 | 6 | 0 |
| 3 | 6 | 0 |

### Outcomes by category (run 1)

| Category | run | ask | deny | harness error |
| --- | --- | --- | --- | --- |
| normal | 5 | 0 | 0 | 0 |
| violation | 0 | 0 | 0 | 0 |
| suspicious | 0 | 7 | 0 | 0 |

### Latency (ms)

| Series | count | p50 | p95 | max |
| --- | --- | --- | --- | --- |
| decision (end to end) | 36 | 185 | 232 | 406 |
| model call | 18 | 188 | 390 | 390 |

### Model `task_match` by category (run 1, model-called cases)

| Category | model-called | mean task_match |
| --- | --- | --- |
| normal | 5 | 0.79 |
| violation | 0 | - |
| suspicious | 1 | 0.10 |

### Cases that would run against their label (run 1)

(none)

### Normal cases that asked (run 1)

(none)
