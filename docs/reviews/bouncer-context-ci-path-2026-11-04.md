# Sol source research for the contextual bouncer experiment

Date: 2026-11-04. Model: gpt-6.1-sol, high reasoning effort.
Base: `773f02c2aff5456354776f9ef0bb60e4161800e1`.
Scope: source-only research; commands below are proposals, not executed model evidence.

**Ścieżka jest wykonalna jako izolowany eksperyment CPU w GitHub Actions, ale obecne workflow nie wykonują treningu ani pomiaru nowego kontraktu.** Potrzebne są mały adapter kontekstowy i osobny job pomiarowy na istniejącym `ubuntu-24.04`. Czas i pamięć takiego treningu pozostają niezmierzone.

Sprawdziłem checkout `feat/bouncer-secret-context`, HEAD `773f02c2aff5456354776f9ef0bb60e4161800e1`. Przeczytałem `AGENTS.md`; niczego nie zmieniłem.

1. **Środowisko i publiczna baza**

   Użyć Python 3.12 i [przypiętych zależności]( /Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/requirements.txt:7). Baza to `convaiinnovations/laya@55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851`; pobieranie obejmuje wagi, encoder i tokenizer — [common.py:13](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/common.py:13). SHA-256 wag jest zapisany w [manifest.json:15](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/manifest.json:15).

   Proponowane komendy **wyłącznie w przyszłym jobie CI**, z nowym katalogiem i bez sekretów repozytorium:

   ```bash
   set -euo pipefail
   EXP="$RUNNER_TEMP/bouncer-context"
   mkdir -p "$EXP"
   export HF_HOME="$EXP/hf" XDG_CACHE_HOME="$EXP/cache"
   export PYTHONDONTWRITEBYTECODE=1 HF_HUB_DISABLE_TELEMETRY=1
   export HF_HUB_DISABLE_IMPLICIT_TOKEN=1
   unset HF_TOKEN HUGGING_FACE_HUB_TOKEN APASSY_BASE_MODEL LAYA_API_KEY
   python3.12 -m venv "$EXP/venv"
   PY="$EXP/venv/bin/python"
   "$PY" -m pip install --index-url https://download.pytorch.org/whl/cpu 'torch==2.14.0'
   "$PY" -m pip install -r tools/basemodel/requirements.txt
   "$PY" -B tools/basemodel/fetch_weights.py
   export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
   ```

   Dobór koła CPU odpowiada [Dockerfile:48](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/Dockerfile:48). Dostępność publicznych plików i pakietów nie była sprawdzana sieciowo.

2. **Dokładny tokenizer — bez ładowania wag**

   Gotowy wzorzec jest w [test_input_boundary.py:21](/Users/rafalw/Dev/apassy-bouncer-context/tests/basemodel/test_input_boundary.py:21): `AutoTokenizer.from_pretrained(<base>/tokenizer, local_files_only=True)` oraz `Agent._to_internal`, bez instancji `Agent`.

   Budżet musi odwzorować [serve.py:112](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/serve.py:112):

   - `serialize_state(state)`, zamiana `mask_token` na spację;
   - tokenizacja z `add_special_tokens=False`;
   - nagłówek przez `build_sequence(..., state_ids=[])`;
   - `len(header) + len(state_ids) <= max_len`, osobno dla każdego pytania.

   W A należy zapisać SHA-256 `tokenizer.json`, konfigurację tokenizera, rzeczywiste `max_len/head_max_len` z przypiętej bazy oraz kompletne token IDs i markery dla fixtures Rust/Python. **Manifest obecnie nie pinuje hasha tokenizera.** Sam test długości nie dowodzi parzystości.

   Istniejąca komenda kontrolna po pobraniu publicznego snapshotu:

   ```bash
   "$PY" -I -B -m unittest discover \
     -s tests/basemodel -p 'test_input_boundary.py'
   ```

3. **Nowa głowa syntetyczna — użyć `train.py` bez wrapperów właściciela**

   [train.py:354](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/train.py:354) ładuje przypiętą bazę; bez `--init` startuje z jej publicznych głów. Encoder pozostaje zamrożony, trenowane są `head.`, `type_emb.`, `scorer.`. Wiersz wejściowy:

   ```json
   {"state":"<canonical sanitized context>","instructions":"<frozen question>","question":"owner_accepts_use","answer":1}
   ```

   **Ten wiersz jeszcze nie działa:** lista sześciu pytań jest zamknięta, a `encode()` używa `QUESTIONS.index()` — [train.py:44](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/train.py:44), [train.py:64](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/train.py:64). Implementacja musi dodać nowe pytanie, kontrolę pełnego budżetu przed `_encode_state()` i manifest `context_contract`. Trener obecnie może dostać tekst obcięty przez pipeline Laya; collate/cache dodatkowo mają limit 512.

   Po tych zmianach istniejący interfejs pozwala wykonać najpierw ograniczoną próbę:

   ```bash
   mkdir -p "$EXP/probe"
   /usr/bin/time -v "$PY" -B tools/basemodel/train.py \
     --data "$EXP/synthetic" --out "$EXP/probe/context.safetensors" \
     --name apassy-context-probe --device cpu --no-amp \
     --batch 2 --epochs 1 --limit 128 --max-steps 4 --warmup 1 \
     --cache-dir "$EXP/probe/cache"
   ```

   Ta próba mierzy wykonalność; pełny trening wymaga usunięcia limitów i ustalenia budżetu na podstawie wyniku.

   Nie używać `train.sh`: buduje Rust i domyślnie wskazuje katalog aplikacji. `local_train.py` wymaga statystyk decyzji właściciela i nie udostępnia `--device` — [local_train.py:70](/Users/rafalw/Dev/apassy-bouncer-context/tools/finetune/local_train.py:70). Starszy `finetune.py` używa `laya.load()` i usuwa zapisany checkpoint — [finetune.py:193](/Users/rafalw/Dev/apassy-bouncer-context/tools/finetune/finetune.py:193), [finetune.py:251](/Users/rafalw/Dev/apassy-bouncer-context/tools/finetune/finetune.py:251).

4. **Dane i pomiar**

   Przygotować osobne syntetyczne `train.jsonl`, `val.jsonl`, zamrożony `test.jsonl`; całe rodziny scenariuszy przypisać do jednego splitu. Obecny generator dzieli po hashu polecenia, co nie zapewnia rozdzielenia rodzin — [gen_data.py:687](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/gen_data.py:687).

   Validation wybiera epokę/progi; test uruchomić dopiero po zamrożeniu głowy i polityki. Minimum i klasy wynikają z [planu:188](/Users/rafalw/Dev/apassy-bouncer-context/docs/design/implementation-plan-bouncer-context.md:188): ≥300 normalnych i ≥300 ryzykownych, niezależny autor testu, brak rodzin z train/validation.

   Potrzebny jest runner **in-process, offline**, bez HTTP: porównanie agregacji faktów z nową głową na tych samych scenariuszach oraz ablation cech/historii. Raportować jakość, ask rate i wszystkie unavailable/timeouts; osobno cold/warm p50/p95, peak RSS, tokeny i snapshot bytes dla 1/3 sekretów oraz granicy kontekstu. Trener już raportuje NLL/Brier/ECE i wybiera najlepszą epokę — [train.py:247](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/train.py:247), [train.py:491](/Users/rafalw/Dev/apassy-bouncer-context/tools/basemodel/train.py:491).

   Istniejący `bench.py` dostarcza pomocnicze percentyle, ale mierzy stare wejścia przez HTTP; jego `make-heads` dodaje szum, **nie trenuje** głowy. CPU Actions nie dostarczy dowodu MPS ani pełnej latencji klienta Rust.

5. **Granica CI**

   [ci.yml:184](/Users/rafalw/Dev/apassy-bouncer-context/.github/workflows/ci.yml:184) instaluje tylko FastAPI/httpx i wykonuje testy bez torch. [bouncer-image.yml:74](/Users/rafalw/Dev/apassy-bouncer-context/.github/workflows/bouncer-image.yml:74) wymaga tokenów Cloudflare i pobiera istniejącą głowę z R2; nie jest izolowaną ścieżką tego eksperymentu.

   Propozycja: osobny ręczny job CPU na już używanym `ubuntu-24.04`, bez sekretów, Docker i publikacji, z timeoutem oraz uploadem raportu/checkpointu. **W obecnym kształcie: nie; po zmianie workflow: możliwy pomiar próbny bez zmiany runnera i nowych usług.** Pełny trening nie ma jeszcze potwierdzonego czasu/RAM ani gwarancji dostępnego limitu Actions.

Nie uruchamiałem instalacji, importów modeli, pobierania, treningu, testów, benchmarków ani Actions. Bez endpointów, danych właściciela, commitów/push/PR. Status checkoutu pozostał bez zmian; wolne miejsce: około **13 GiB**.

## Parent verification after the source review

On 2026-11-04 the parent fetched only public JSON metadata: PyPI returned HTTP 200 for torch 2.14.0, laya 0.3.20 and tokenizers 0.23.2; the Hugging Face model API returned HTTP 200 and revision `55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851` for the pinned public base. No model weights were downloaded or imported. This establishes public metadata availability, not wheel installation, model compatibility or measured model quality.
