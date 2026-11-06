# Przegląd metody kalibracji cached head po timeout — 2026-11-04

HEAD `1b9cbd9886a710ce4ba10f17229fb317c62fb460`, draft PR #104. Przegląd źródłowy jednej propozycji metody. Bez modelu, testów, CI i sieci. N2–N4, poprawka kosztów i soundness projekcji pozostają zatwierdzone (`bouncer-context-n2-budget-review-2026-11-04.md`); tego nie otwieram ponownie.

## Werdykt: ACCEPT, z warunkami poniżej (W1–W8)

Metoda daje tylko **estymatę runtime do eligibility**. Nie jest to górna granica sprzętowa ani dowód stabilności. Nie daje też podstaw do żadnej oceny jakości ani bezpieczeństwa. B pozostaje UNSUPPORTED, dopóki jeden ograniczony probe na nowym SHA nie zwróci ELIGIBLE.

Uzasadnienie:

1. **Ta decyzja dotyczy zasobów, a nie jakości.** Projekcja wybiera tylko `g` i decyduje, czy uruchomić ograniczony full. Jeżeli czas zostanie niedoszacowany, nadal obowiązują twarde limity: 5400 s/head, 300 min, L1 i 60% budżetu. Trening przerwie się wtedy przed freeze/held-out. Kosztem jest jedna ograniczona próba. Nie ma wpływu na progi, bramki ani held-out.
2. **Skalowanie ×4 jest strukturalnie konserwatywne dla policzalnej pracy.** W `_cached_head_step` każdy element jest dopełniany do 512. Dlatego FLOPs head (attention liczone osobno dla każdej sekwencji), collate, odczyt cache (jeden `torch.load` na element) i loss/backward rosną liniowo z batch. Stałe koszty kroku, czyli `zero_grad`, `clip_grad_norm_` i `AdamW.step` na tych samych parametrach, nie zależą od batch. Mnożnik ×4 liczy je więc czterokrotnie. Nieliniowy może być tylko efekt hierarchii pamięci i alokatora (4× większe aktywacje; RSS 9.47 GB, 27 M minor faults). Takie zjawisko wykrywa rzeczywisty spot32 na pełnym kształcie.
3. **Jeden spot32 nie jest p95, lecz testem przesłanki liniowości.** Dlatego W4 wymaga odmowy, gdy spot32 przekracza `1.3 × scaled8`. W takim przypadku jedyną podstawą byłaby pojedyncza próbka, czego nie akceptujemy. Pozostałe ryzyko, czyli pojedyncza próbka spot ≤ 1.3× wartości skalowanej, pokrywają `max(...)`, istniejący margines 1.3 i twarde deadline'y. Odrzucenie wymagałoby rozkładu batch32, którego w 120 s nie da się zmierzyć, a wcześniejsza projekcja też była estymatą z marginesem. Odrzucenie z tego powodu stawiałoby tej metodzie wymaganie, którego nie spełniała wcześniej zatwierdzona metoda.
4. **Mniej pracy w tym samym limicie, lecz bez gwarancji, że się zmieści.** Obecnie wykonywane jest 5+5 kroków batch32 (train/val) i 5 kroków scoring1. Wariant wykonuje około 2.25+2.25 ekwiwalentu batch32 i te same 5 kroków scoring1, czyli ~45% pracy head. Poprzedni przebieg nie zachował fazy, więc nie wiadomo, czy to wystarczy. Kolejny timeout jest wynikiem końcowym (W8).

## Kontrakt implementacji (warunki)

**W1. Zakres i kolejność w jednym `cached_head_timings(items, seconds=120)`.** Bez zmian pozostają: snapshot, setup, `deadline()` przed/po każdym kroku, restore oraz `0 < seconds <= 120`. Kolejność:
`training8` (2 warmupy + 3 próbki, `items[:8]`) → `validation8` (2+3, `items[:8]`) → `scoring1` (2+3, `items[:1]`) → `spot32.training` (1 krok, wszystkie 32, bez warmupu) → `spot32.validation` (1 krok, wszystkie 32, bez warmupu).
Spot jest wykonywany po krokach batch8. Alokator i stan AdamW są już wtedy rozgrzane, ale pierwsza alokacja kształtu 32 wlicza się do spotu, co działa w kierunku konserwatywnym. Wszystkie kroki używają tego samego `_cached_head_step`: FP32 `head_logits`, prawdziwa maska i markery, pad do 512, odczyt z cache, loss, backward, clip, ten sam optimizer i offline. Brak wpisu w cache oznacza odmowę przed forward. Encoder nie jest wywoływany.

**W2. Pola wyniku `cached_head`** (wszystkie wymagane):
```
method: "batch8x4_max_batch32_spot_v1"
sequence_length: 512, unit: "seconds_per_batch", warmups: 2,
encoder_in_measured_step: false, provenance, includes, threads,
seconds: 0 < s <= 120            # cały zakres, łącznie z setup i restore
projection_batch_size: 32        # brak top-level batch_size, aby nie sugerować pomiaru 32
training:   {batch_size: 8, samples: 3, p50_seconds, p95_seconds}   # surowe
validation: {batch_size: 8, samples: 3, p50_seconds, p95_seconds}   # surowe
scoring:    {batch_size: 1, samples: 3, p50_seconds, p95_seconds, p95_seconds_per_row}
spot32: {training:   {batch_size: 32, samples: 1, warmups: 0, single_sample_seconds},
         validation: {batch_size: 32, samples: 1, warmups: 0, single_sample_seconds}}
scaled_batch8_to32: {factor: 4, training: 4*p95(training8), validation: 4*p95(validation8)}
projection_step_seconds: {source: "max(scaled_batch8_to32, spot32)", training, validation}
```
Rekord spot nie może zawierać kluczy `p50_seconds` ani `p95_seconds`.

**W3. `project_workload`** akceptuje tylko `method` z W2. Stary kształt rekordu i każdy inny odrzuca z `Unsupported('cached timing method')`. Wartości pochodne wylicza **wyłącznie z surowych pól**, a zapisane `scaled_batch8_to32` i `projection_step_seconds` muszą się z nimi zgadzać (`rel_tol=1e-12`); w przeciwnym razie UNSUPPORTED. `train_step = max(4·p95(training8), spot.training)`, a `val_step` liczony jest analogicznie. Scoring działa bez zmian: `batch_size == 1`, p95. Wzór komponentów pozostaje bez zmian.

**W4. Fail-closed.** UNSUPPORTED i brak freeze następują przy: timeout, braku lub niepełnym rekordzie (samples ≠ 3 dla batch8/scoring, ≠ 1 dla spot), złym `batch_size`, wartości nieskończonej, ≤ 0 lub nie-float, `p95 < p50`, niezgodności wartości pochodnych oraz gdy **`spot32.X > 1.3 × scaled_batch8_to32.X`** dla X ∈ {training, validation} (reason `batch scaling outside calibrated regime`). Ten ostatni warunek jest zaostrzeniem i nie wprowadza nowego parametru.

**W5. Diagnostyka częściowa nie może wpływać na eligibility.** Przy wyjątku lub timeout raport może zawierać `diagnostics.cached_head_partial = {phase, completed_calls, elapsed_seconds, eligibility: false}`. Nigdy nie trafia on pod klucz `cached_head` i nie jest czytany przez `project_workload` ani przez workflow. Wykonanie `deadline()` w `finally` po restore **nie może maskować** pierwotnego wyjątku: przy wyjątku w toku restore jest wykonywany, po czym ponownie zgłaszany jest pierwotny wyjątek. Wynik nadal jest UNSUPPORTED. Restore wag, `requires_grad`/`grad`, trybów, RNG torch i Python oraz cleanup cache odbywa się bez zmian także po błędzie.

**W6. Wybór `g` w workflow** (wszystkie cztery kopie bloku eligibility, linie ~239/489/620/832, zmienione identycznie): największe `g ∈ [400, 800]`, dla którego jednocześnie
`projection·g/800·1.3 <= 0.6·300·60` **oraz** L1 `(encoder_cache_seconds + training_cache_io_seconds/2)·g/800·1.3 <= 5400`.
Brak takiego `g` oznacza, że full nie startuje. Asercje workflow zastępują `batch_size == 32 / samples == 3` dla train/val polami z W2, przeliczają W3/W4 i wymagają `0 < seconds <= 120`.

**W7. Wystarczające checki stdlib/fake** (później, przez `heavy-check`; teraz NOT_RUN):
- istniejące testy `measure_cached_steps` (warmupy wykluczone, deadline, zegar) bez zmian;
- rzeczywista ścieżka z fake interfejsami: `head_logits` 17×, `optimizer.step` 6×, `cache.get` 149× (40+40+5+32+32), `encoder_states` nie jest wywoływany, `AdamW` wywołany raz tylko z parametrami head, zapisane batch_size 8/8/1/32/32, w spot brak kluczy p50/p95;
- wstrzyknięty błąd w każdej z 5 faz: pełne restore stanu i RNG oraz zgłoszenie pierwotnego wyjątku;
- zegar przekraczający 120 s w każdej fazie: `wall limit`, brak `cached_head`, partial ma `eligibility: false`;
- `project_workload`: odrzuca każdy przypadek z W4; dla poprawnego wejścia testuje gałąź „scaled wygrywa” i „spot wygrywa (≤1.3×)”; zwiększenie dowolnego surowego czasu nie zmniejsza projekcji;
- wybór `g`: fixture, w którym limit 10800 przepuszcza, a L1 obniża `g` albo daje `None`; raport zawierający tylko partial daje brak `g`;
- cztery bloki workflow mają identyczny zestaw asercji.
Te checki weryfikują logikę i fail-closed, ale nie zastępują pomiaru.

**W8. Jeden rzeczywisty ograniczony probe** na nowym SHA X z zielonym CI, w obecnych limitach (120 s head, 40 min probe), offline i bez prywatnych wag/R2. ELIGIBLE wymaga kompletnego `cached_head` według W2–W4, zgodnego przeliczenia i `g` według W6. Każdy inny wynik oznacza, że **B pozostaje UNSUPPORTED, bez kolejnych powtórek ani zmian metody dla ELIGIBLE**. Grupa/full wymaga tego samego SHA X.

Odpowiedź na pytanie wprost: tak, `max(scaled8, spot32)` z W4, bez kolejnego długiego pomiaru, jest uczciwą podstawą **wyłącznie dla runtime eligibility**. Nie wolno go cytować jako p95 batch32, kosztu treningu ani wyniku wydajności.

## Niezmienione granice

120 s cached head, 120 s encoder, 40 min probe, 300 min train, 5400 s/head, 6 GiB cache, margines 1.3 i 60% budżetu; brak nowych runnerów i płatnych usług; brak prywatnych wag i R2. Bez zmian pozostają też: 4 epoki full, batch32 w treningu, 400–800 grup, threshold selection, bramki quality/security, zewnętrzny freeze z jednym przejściem held-out oraz ścieżka produkcyjna. C/D/E pozostają zablokowane do B i przeglądu. L1 obowiązuje dodatkowo jako automatyczny warunek. Obecnie nie da się go obliczyć, bo pierwsza kalibracja nie dała składników.

## NOT_RUN

Implementacja, build, testy (fake i stdlib), install, model, torch, tokenizer, wagi, CI, probe, full, koszt, held-out, commit, push i dispatch. Przeczytano tylko raport Sola, `context_train.py` (`timing_summary`, `measure_cached_steps`, `project_workload`, `probe_timings`, `_cached_head_step`, `cached_head_timings`), odpowiednie fragmenty `test_context_budget.py` i asercje `bouncer-context-experiment.yml`. Nie czytano held-out, jego manifestu ani generatora; nie otwierano `design/reviews/`. Zmieniony plik: tylko ten raport.

PR https://github.com/wydrox/apassy/pull/104, head 1b9cbd9886a710ce4ba10f17229fb317c62fb460, checks probe failed (120s calibration), source N2–N4 approved; B unsupported.
