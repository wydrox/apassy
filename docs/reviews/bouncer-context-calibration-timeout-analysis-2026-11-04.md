# Diagnoza timeoutu kalibracji context — 2026-11-04

HEAD: `1b9cbd9886a710ce4ba10f17229fb317c62fb460`, PR #104. Diagnoza źródłowa i lokalne dowody; bez wykonania modelu. **B pozostaje UNSUPPORTED. Nie znalazłem uzasadnionej optymalizacji implementacyjnej zachowującej cały obecny kontrakt pomiaru.**

## Dowód i granice

- Lokalny log `/tmp/apassy-pr104-probe-1b9cbd98.log` potwierdza compiled replay i G1 actual Rust host extraction: 24 testy, OK bez skipów; pełny tokenizer: 3 testy, OK bez skipów. Jest to syntetyczne G1, nie held-out ani wynik jakości.
- `/tmp/apassy-context-probe-41852508456/probe/training-report.json` zawiera wyłącznie `mode=probe`, `outcome=UNSUPPORTED`, `reason="cached timing wall limit"`. Log zapisuje ten sam wynik. Run 41852508456 / job 126652259018; lokalne podsumowanie `bouncer-context-probe-1b9cbd98-2026-11-04.json` wiąże source HEAD z checkout/tested SHA `63acf1caac900b3dcdaea25ce3b13d7a4d9e05c5` — nie utożsamiam tych SHA.
- `evidence/training-time.txt`: proces 195.72 s wall, user 315.55 s, sys 42.15 s, CPU 182%, maxRSS 9471780 KiB; exit 3. Swaps 0, major faults 1, minor faults 27451855. To statystyki całego procesu, nie samej kalibracji. `evidence/probe-costs.json`: 397.995 s obejmuje szerszy zakres joba, nie czas treningu.
- Z kolejności kodu wynika, że kalibracja nie wróciła do pętli `Scorer.train` (`context_train.py:723–727`). Brak ukończonego treningu, freeze/checkpointów, kosztu i held-out. Exit 3 jest też stałym kodem zakończenia CLI; sam nie dowodzi poprawnego ukończenia. Weryfikacja completion w logu kończy się AssertionError.
- Komunikat identyfikuje osobny deadline cached head, nie encoderowy `probe timing wall limit`, quality FAIL, NameError ani wcześniejsze `cost_arm_failed`. Dotarcie tutaj dowodzi zakończenia encoderowej części `probe_timings`, lecz jej wynik nie został zachowany. Wcześniejsze około 64 s encodera to kontekst podany w zleceniu, nie pomiar tego przebiegu. Nie wolno odjąć go od 195.72 s i ogłosić czasu kalibracji.
- **Etap wewnątrz kalibracji nie był logowany.** Nie wiadomo, ile warmupów/próbek ukończono. Ten sam deadline sprawdzany jest po setupie, przed/po kroku oraz po odtworzeniu stanu w `finally`; ostatni check może też zastąpić wcześniejszy wyjątek tym komunikatem. Nie dowodzi to awarii w konkretnej operacji. Deadline jest sprawdzany pomiędzy operacjami, nie przerywa trwającego kroku dokładnie w 120. sekundzie.

## Konkretne koszty w źródłach

`context_train.py:385–437` najpierw koduje 32 elementy w batch1 i batch8, zapisuje fp16 cache, a następnie wywołuje `cached_head_timings`. Encoder ma własne 120 s; koszt wcześniejszego kodowania nie zużywa osobnego limitu cached head.

`cached_head_timings` (`:474–530`) w swoim limicie 120 s wykonuje snapshot FP32 trenowanych parametrów, zapis flag/gradientów/trybów i RNG, setup AdamW, kolejno training32, validation32, scoring1 oraz odtworzenie stanu. Każdy z trzech rodzajów kroku wymaga 2 warmupów i 3 próbek (`measure_cached_steps`, `:79–92`). Pełna kalibracja oznacza 15 wywołań głowicy: 5 treningowych z backward/clip/AdamW, 5 walidacyjnych z loss i 5 scoringowych. P95 z trzech próbek jest maksimum.

Każdy krok ponownie wykonuje collate, padding do 512 i odczyt cache (`:439–472`). `features` (`:254–269`) tworzy bufor FP32, ładuje osobny plik przez `torch.load` na element, konwertuje fp16→FP32 i kopiuje dane. Przy ukończeniu całości to 325 odczytów (10×32 + 5×1), niezależnie od trafień systemowego page cache. Nie ma encodera w kroku: brak wpisu cache powoduje odmowę przed forward.

`train.head_logits` (`train.py:205–218`) dodaje type embedding i uruchamia warstwy head na całym tensorze batch×512 z rzeczywistą maską, potem gather markerów i scorer. Maska nie jest źródłową gwarancją pominięcia obliczeń paddingu. Sekwencja 512 zwiększa koszt attention i aktywacji/backward; dokładny koszt zależy od backendu, którego tutaj nie profilowano. `common.py:19,52–54,79–90` ogranicza snapshot i odtworzenie do head/type_emb/scorer; nie ma podstaw do diagnozy kopiowania całego encodera w tym snapshotcie.

**Najbardziej prawdopodobna hipoteza:** dominują obliczenia FP32 head batch32/seq512, zwłaszcza pięć kroków treningowych z backward, i związana z nimi alokacja/pamięć; dodatkowy koszt to cache IO/konwersje, walidacja oraz snapshot/restore. CPU 182% jest zgodne z pracą na dwóch wątkach, a wysoki RSS i minor faults z dużym ruchem pamięci, ale nie lokalizują kosztu. Brak dowodu na OOM, swapping lub dominujący fizyczny odczyt dysku. Nie wiadomo nawet, czy osiągnięto walidację. To ranking hipotez ze struktury kodu, nie profil czasowy.

## Minimalna poprawka przy obecnym kontrakcie

**Brak uzasadnionej poprawki przyspieszającej.** Nie widać zbędnego encodera w mierzonej ścieżce. Usunięcie odczytów cache/collate, prealokacja zamiast rzeczywistego kroku, skrócenie sekwencji, mniej warmupów/próbek, zmiana dtype/optimizer/backendu albo wyłączenie backward zmieniałyby mierzoną pracę lub wymagały dowodu równoważności. Przesunięcie setupu/restore poza limit zmieniłoby zakres deadline. Nie rekomenduję żadnej z tych zmian jako naprawy tego wyniku.

`test_context_budget.py:99–111,114–264` sprawdza zegarem i sztucznymi interfejsami kolejność, liczbę wywołań, cache-only oraz odtworzenie stanu. Nie mierzy prędkości CPU i nie daje dowodu, że realny model mieści się w 120 s. Workflow sprawdza batch32/seq512, 2 warmupy, 3 próbki, scoring1, provenance i ≤120 s oraz przelicza projekcję; nie wolno osłabić tych asercji bez nowej zgody na metodę.

## Jeden wariant metody do ewentualnego przeglądu Opusa

Wyłącznie propozycja, **nie implementacja i nie uprawnienie do ELIGIBLE**: zmierzyć training8 i validation8 przy seq512 (po 2 warmupy + 3 próbki), pozostawić scoring1 (2+3), a w tym samym wspólnym limicie 120 s wykonać dodatkowo niezależny rzeczywisty spot-check training32 oraz validation32 na pełnych 32 elementach cache. Zachować rzeczywistą ścieżkę FP32, maski/markery, IO, loss/backward/clip/AdamW, offline i pełne odtworzenie modelu/RNG. To jawna zmiana metody: nie spełnia obecnego wymogu 2+3 na batch32.

Raportować osobno surowe czasy batch8, oszacowanie `scaled_batch8_to32 = 4 × p95(batch8)` i surowe spot-checki batch32. Kandydat do projekcji używałby dla train/val maksimum z tego oszacowania i odpowiedniego spot-checku batch32. Timeout, brak spot-checku lub niepełne próbki zawsze pozostawiają UNSUPPORTED; realny wolny batch32 nadal może zablokować wynik. **Maksimum tych liczb nie jest dowiedzionym górnym ograniczeniem kosztu batch32:** skalowanie może być nieliniowe, a pojedynczy spot-check nie daje p95 ani stabilności po warmupach. Opus musiałby zatwierdzić metodę i wymóg niezależnego empirycznego uzasadnienia konserwatywności przed wykorzystaniem do eligibility. Nie zakładam, że wariant zmieści się w 120 s. Jeżeli takiego uzasadnienia/pomiaru nie da się uzyskać w zatwierdzonych zasobach, uczciwym wynikiem pozostaje B UNSUPPORTED.

## Następne checki i status

Przeczytany zaakceptowany `bouncer-context-n2-budget-review-2026-11-04.md` zamyka N2–N4 i soundness budget w źródłach. Timeout tego nie cofa, ale nie spełnia bramki runtime. Przed jakimkolwiek full nadal wymagane są green CI oraz eligible probe na tym samym X (400–800 grup), a dodatkowo L1: `(encoder_cache_seconds + training_cache_io_seconds/2) * g/800 * 1.3 <= 5400`. Teraz brakuje pełnych czasów i składników projekcji, więc L1 nie da się policzyć. Nie podnosić limitów, nie ponawiać dispatchu na X wbrew zasadzie jednego probe/full. PR pozostaje draft; brak autoryzacji merge/activation.

Kolejny krok bez modelu: źródłowy przegląd Opusa wyłącznie powyższej zmiany metody, jej provenance, fail-closed, skalowania i zachowania stanu. Ewentualne checki stdlib (przez heavy-check) mogą później sprawdzić odrzucanie niepełnych/nieprawidłowych pomiarów i arytmetykę projekcji; nie zastąpią empiryki batch32. W tym zadaniu ich nie uruchamiano.

Wykonane read-only: `git rev-parse HEAD` (zgodny), `git status --short`, `git diff --name-only` (bez zmian tracked), ograniczone `rg`/`nl`/`sed`/`cat` wskazanych źródeł i dowodów, `df -k /System/Volumes/Data` (11075384 KiB wolne, około 10.56 GiB). Bez fetch/sieci/odpytywania CI lub innych tasków. Nie czytano design/reviews ani zabronionych plików held-out/manifestu/generatora.

Changed files wyłącznie: `docs/reviews/bouncer-context-calibration-timeout-analysis-2026-11-04.md`. Istniejące nieśledzone raporty pozostawiono bez zmian. NOT_RUN: build, testy (także fake unit i stdlib check), install, model/torch imports, tokenizer, wagi, sejf/dane właścicielskie, CI, probe, full, cost, held-out, commit/push/dispatch. Nie powstały artefakty build ani procesy do sprzątania.

PR https://github.com/wydrox/apassy/pull/104, head 1b9cbd9886a710ce4ba10f17229fb317c62fb460, checks probe failed (calibration timeout), review N2–N4 approved; B unsupported.
