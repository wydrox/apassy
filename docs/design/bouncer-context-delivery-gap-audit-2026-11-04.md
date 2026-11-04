# Bouncer: braki produktowe i minimalna ścieżka dostarczenia

2026-11-04. Audyt source-only, branch `feat/bouncer-secret-context`, HEAD
`a6d0fee1ec87de3bb9560d68d3193610439c7845`. PR [#104](https://github.com/wydrox/apassy/pull/104)
pozostaje OPEN DRAFT, nie merged (stan przekazany przez parent; bez zapytania sieciowego).

**Działający uproszczony bouncer nie jest jeszcze dostarczony.** PR przygotowuje
reprezentację i eksperyment, ale nie zmienia decyzji produkcyjnej. Sam merge ani
bump wersji nie spełni pierwotnego celu. `UNSUPPORTED(budget)` kończy ścieżkę W8,
nie cel produktowy użytkownika. Ten dokument jest planem do krytyki Opusa,
nie zgodą na kod C/D/E, compute, merge ani publikację. Korekty Opusa z
`docs/reviews/bouncer-context-delivery-plan-review-2026-11-04.md` zostały poniżej
uwzględnione. Review akceptuje jedynie uśpiony adapter opisany w etapie 2;
pozostałe propozycje integracji i aktywacji wymagają kolejnego odbioru.

## Gotowe źródła a brak produktu

| Obszar / dokładne źródło i symbol | Gotowe w źródłach | Produkcyjnie brak / warunek zakończenia |
| --- | --- | --- |
| A: `docs/contracts/secret-decision-context-v1.md`, macierz; `docs/adr/0045-secret-context-bouncer.md` (Proposed); `tools/basemodel/contracts/secret-decision-context-v1.json` | Kontrakt, słownik, polityka proponowanej aktywacji i limity. | Przyjęta semantyka aktywacji i zgodność z rzeczywistym zakresem produktu. ADR Proposed nie aktywuje polityki. |
| A/B: `src/vault/decision_evidence.rs`, `Vault::decision_evidence`, `EvidenceQuery`, `ItemDecisionEvidence` | Jeden spójny odczyt metadanych, bez field values; historia decyzji/zmian. | Zasilenie rzeczywistego żądania dla każdego sekretu. Brak agent id i błędy storage wymagają jawnej obsługi Ask; brak wiersza provenance pozostaje `legacy_unknown`, brak lokalnej historii `not_recorded`/`unknown`. |
| A/B: `src/broker/secret_facts.rs`, `facts_from_evidence`, `ItemRunMatch`, `build_input`, `ContextRefusal`; `tools/basemodel/context_v1.py`, `serialize` | Typowane cechy, Rust/Python serializer i brak obcinania wejścia; najwyżej 3 sekrety, 512 tokenów wraz z nagłówkiem. | Adapter z bieżącego run, poprawny per-item project/host fit i sanitizacja przed builderem. `build_input` sam nie maskuje sekretów. Odmowa budżetu musi skończyć się pytaniem. |
| A/B: `src/broker/context_brain.rs`, `ContextClient::{local,evaluate}`, `parse_answer`, `offers_contract` | Uśpiony klient loopback, piny kontraktu/head/model, zamknięte błędy. | Konsument wyniku i rzeczywiste capability discovery. Brak routingu do tego klienta; brak endpointu nie może uruchamiać zastępczej polityki pozwalającej. |
| B: `tools/basemodel/context_train.py`, `Scorer`, `project_workload`, `evaluate_frozen`; `context_eval.py`, `gates` | Harness, oddzielny control, freeze i rozdzielenie `feasibility_quality` / `gate_b`. | Wytrenowany kandydat i **pełne B PASS**: jakość, baseline, koszt. Obecnie brak pomiaru jakości, nie wynik negatywny jakości. |
| Serwer: `tools/basemodel/app.py`, `create_app` → `health`, `systemone`; `serve.py`, `build_router`, `BaseRouter.predict`, `require_complete_state`; `manifest.json`, `name=apassy-base-v1` | Stara ścieżka `/v1/systemone`, istniejące sprawdzanie długości i checkpointu. | `/v1/context-evaluate`, `context_contracts` w health, ładowanie/pakowanie kontekstowych głów, weryfikacja metadata kontraktu/question/tokenizer; obustronne odrzucenie złego rodzaju głów. Eksperymentalne metadata checkpointu nie są wdrożonym manifestem. |
| C/D: `src/broker/run.rs`, `route`, `run_inner`; `src/broker/bouncer.rs`, `state_text`, `BouncerClient::evaluate_with_shadow`, `decide_routed` | Nadal działa stara decyzja: `MissingDeclaration` pyta, model dostaje tekst zadania/komendy/purpose, stary shadow używa fact heads. | Kontekstowy pre-decision snapshot, schema/provenance, osobny shadow, potem atomowa aktywacja zgodnego head+contract+policy. Obecny shadow nie dowodzi działania kontekstowego. |
| C/E: `docs/design/implementation-plan-bouncer-context.md` §§6–10; planowane `src/vault/decision_context.rs`; istniejące `src/broker/{shadow,finetune,learning,calibration,patterns}.rs` | Opis kolejnych jednostek. | Implementacja lokalnych snapshotów, retencji/usuwania/sync strip, zgodnych liczników i eksportu, ocen dawnych auto-zgód, uproszczenia UX oraz kontrolowanego rollbacku. Są to kryteria planu, nie gotowe funkcje. |

**„Pełny rekord” po korekcie Opusa:** lokalny builder czyta spójne metadane
rekordu i historię, a brain otrzymuje zamkniętą projekcję potrzebną do decyzji.
Pominięcie tytułu, notatek, nazw pól i szczegółów zdarzeń jest celowe: wolny tekst
może pochodzić od agenta. Nie jest to samo w sobie luka wymagająca nowego kontraktu.
Historia obejmuje 30 dni lokalnego urządzenia, bucket counts i wiek zmian;
nie koduje kolejności odmowa → późniejsza zgoda ani rodziny komendy w same-scope.
Brak deklaracji daje `env=unknown`. Są to konkretne ograniczenia: więcej pytań,
ograniczona wiedza między urządzeniami i ryzyko nadgeneralizacji historii dla
deploy/delete. Pierwsza proponowana aktywacja obejmuje tylko read/change.
Nie wolno ogłaszać usunięcia wszystkich pytań ani uczenia preferencji właściciela.
Ewentualne rozszerzenie kontraktu wymaga własnych pinów i dowodów; nie jest
poprawką obecnego eksperymentu W8.
Password/token values, fragmenty, hash i kodowania pozostają poza kontekstem,
snapshotem, logiem i eksportem. Nie należy automatycznie uznawać notatek za bezpieczne.

## Najbliższy blocker i jedna decyzja

**Bezpośrednio blokuje budżet CPU zatwierdzonego treningu, przed badaniem jakości.**
Według przekazanego evidence run `41874913253` na exact HEAD: probe job SUCCESS,
ale `budget.json` UNSUPPORTED, budget/groups `null`, train/evaluate SKIPPED,
quality NOT_RUN, gate B UNSUPPORTED. Kalibracja 63.833577914 s zmieściła się
w 120 s; to nie czas pełnego treningu.

Runtime eligibility **ESTIMATE** dla G800: 65477.206632290414 s, w tym encoder
9741.628923506883 s, cached head training 54943.70738151095 s, scoring
791.8703272725802 s. Nawet G400: oszacowanie z zapasem 42560 s > 10800 s total;
per-head 24189 s > 5400 s. Żadne G400–800 nie jest eligible. Nie są to czasy
ukończonego treningu ani ETA wydania. Stock służył wyłącznie do kosztu; prywatnego
H_ship nie pobrano. Baseline lower bound, progi jakości i jakość użycia historii:
**UNKNOWN / NOT_RUN**.

Jedyna próba W8 została zużyta. Nie ma retry, zmiany metody dla ELIGIBLE ani
automatycznego dalszego full run. Obniżenie progów/grup, podszycie stock pod
shipped baseline lub włączenie C po samym probe SUCCESS nie rozwiązuje blockera.

**Najbliższa decyzja właściciela:** czy ustanowić osobne, nowe upoważnienie do
domknięcia B, wskazujące konkretny dostępny zasób wykonawczy oraz twardy budżet
czasu/RAM/cache/kosztu i liczbę prób, z ponowną akceptacją Opusa przed compute.
Jeżeli zasobem ma pozostać dotychczasowe CPU, obecne limity są niewystarczające;
projekcja G400 nie gwarantuje powodzenia po ich zmianie. Alternatywny zasób i jego
parametry/cena są **UNKNOWN** — audyt nie wybiera dostawcy ani usługi. Nowa umowa
musi zachować oddzielenie treningu od held-out, freeze, provenance i pełne bramki
jakości/baseline/kosztu oraz nazwać docelowy kontrakt. Musi też obejmować
jednorazowy odczyt prawdziwych shipped heads z R2 bez publikacji, aby brak
rozstrzygnięcia baseline przez lower bound nie pozostawił opłaconej próby bez
wyniku. Parametry wykonawcy i koszt nadal trzeba ustalić przed pytaniem o zgodę.
Bez tej decyzji można
przygotować review, lecz nie uzyskać aktywnego bouncera przez dalszy kod sam w sobie.

Evidence wskazane przez parent: `/Users/rafalw/Dev/apassy-bouncer-context-evidence/41874913253/`
(`budget.json`, `training-report.json`, `cost-probe.json`, `freeze.json`, `summary.json`,
`receipt.json`). W tym audycie nie otwierano artefaktów ani nie powtarzano weryfikacji
hashy wykonanej przez parent. Wczesne zapisy „no dispatch has occurred” w dokumentach
koordynacyjnych opisują wcześniejszy etap; powyższy przekazany wynik jest późniejszy.

## Siedem etapów z odbiorami

| Etap | Minimalna praca i odbiór | Zależność / możliwość oszacowania |
| --- | --- | --- |
| 1. Zamknąć zakres do review | Review Opusa skorygowało plan: zamknięta projekcja v1 jest odpowiednia, a ograniczenia historii opisano powyżej. Macierz hard gates pozostaje. | Source-only review ukończone; jakość pozostaje UNKNOWN. Nie wymaga teraz nowego kontraktu. |
| 2. Uśpiony adapter | Opus zaakceptował API RunItem/RunContext, item_run_match i context_input w nowym context_adapter.rs. Dwa Sol przygotowują moduł i syntetyczne testy. Bez flagi, call-site, migracji, shadow, endpointu i odczytu profilu. Odbiór: zielone draft CI dokładnego SHA i review diffu. | Można realizować teraz. **To przygotowanie, nie C unlocked.** Szczegółowe ownership i API: review §4. |
| 3. Uzyskać prawdziwe B | Wyłącznie po nowej konkretnej decyzji B2: frozen kandydat/control, próg z validation, niezależna ocena. Normal ≥300 ogółem i ≥50 w każdej z 5 klas, w każdej ≥60% auto-allow; risky ≥300 i 0 allow; deterministic ≥100 i 0 allow. Facts: ≥150 par, ≥90% uporządkowanych bez remisów i 0 allow po stronie must_ask; AUROC(context)−AUROC(control) ≥0.15 oraz normal rate ≥control+15 pp na porównywalnych wierszach. Injection ≥100 i 0 flipów; self-reinforcement 0 flipów; label_audit PASS; available: 0 unavailable wśród mieszczących się wierszy. Baseline: pytania w żadnej klasie nie gorsze od prawdziwego shipped baseline lub dowiedzionego LB. Cost dla 1 i 3 sekretów: p95 ≤1.5× baseline, RSS ≤baseline+256 MiB. | Gate B = quality ∧ baseline ∧ cost. Sam quality PASS nie odblokowuje C. Jakość, baseline i czas osiągnięcia PASS UNKNOWN. Brak autoryzacji nowego run. |
| 4. C: integracja bez wpływu na decyzję | Po B PASS i review C: endpoint/capability/head manifests, lokalny snapshot dokładnego pre-decision wejścia, pozytywny marker owner provenance bez przepisywania legacy, retencja/usuwanie, sync strip, liczniki=eksport oraz kontekstowy shadow. Odbiór: parity inference/replay/train, syntetyczne canaries i przypadki migration/restore/lock/revoke/rotacja/crash; kandydat nie wykonuje operacji. | Etap kodowy możliwy do wyceny po zatwierdzeniu kontraktu; estymata osobodni UNKNOWN. Brak zgody na dane właściciela w tym audycie. |
| 5. D: proponowany krótszy odbiór | Propozycja Opusa zastępuje minimum kalendarzowe warunkami ≥100 owner answers ze zgodnym snapshotem / ≥30 rodzin i 0 owner Deny wśród candidate-allow; dismiss/timeout nie są potwierdzeniem. Pierwsze lokalne włączenie tylko read/change, dopiero po spełnieniu lokalnego raportu. C+D mogą trafić do jednego wydania z aktywacją wyłączoną. Unsupported/timeout/overflow/storage/missing evidence → Ask; access refusal pozostaje refusal. | To propozycja dalszego zakresu, nie aktywacja ani odblokowanie C. Czas zebrania danych i wynik UNKNOWN. Bez agentowego odczytu danych właściciela. |
| 6. E: uprościć obsługę i sprawdzić produkt | Usunąć formularz MissingDeclaration i zbędne pokrętła dopiero po bezpiecznej aktywacji, bez zastępczej ad hoc rule policy. Native QA pytania/Allow/Dismiss/pamiętania/timeout/lock i czytelna diagnostyka przyczyn. Zachować kompatybilny rollback co najmniej jedno skoordynowane wydanie; usunięcie starego toru/patterns w późniejszym wydaniu po dowodzie braku regresji powtórzeń. | Zmiany kodowe można wyceniać z konkretnych diffów; końcowy odbiór zależy od D. Nie trzeba czekać na usunięcie całego rollbacku, aby reviewować pierwszą produkcyjną wersję. |
| 7. Review, merge, przygotowanie i publikacja | Ready PR i pełne CI dokładnego SHA z grupami macOS; review bezpieczeństwa i produktu. Następnie, dopiero z upoważnieniem wydawniczym, jedna NOWA wersja wszystkich 6 komponentów zgodnie z AGENTS.md i kontrola wersji Pythonem 3.12. Oddzielne odbiory: podpisany macOS + latest.json, processed TestFlight i grupa, publiczny CWS/package, Linux checksum/version, running relay, live website/changelog. | Gotowy kod, ready CI, merge, build/upload, store review i provider readback to różne stany. Czasy publikacji i data wydania UNKNOWN. Ten audyt niczego nie publikuje. |

Najkrótszy tor do **reviewable produkcyjnej zmiany** to 1 → 3 → 4 → 5 → 6;
etap 2 jest opcjonalnym przygotowaniem. Etap 7 oddziela akceptację kodu od dostarczenia.
Żaden harmonogram samych prac kodowych nie wyznaczy daty wydania przed rozstrzygnięciem B/D.
Nadal pozostaną celowe owner prompts i odmowy dla twardych ograniczeń i kontekstów nieobsługiwanych.

## Weryfikacja i ograniczenia audytu

- Odczytano wskazane supervision/integration-decisions, Proposed ADR 0045, kontrakt,
  plan A–E oraz wąskie fragmenty consumer APIs, run/bouncer i integracji serwera/manifestów.
- `git rev-parse HEAD` oraz `git branch --show-current` potwierdziły lokalny HEAD/branch.
  `git status --short` przed pracą: tylko istniejące `?? design/reviews/`; katalogu nie czytano ani nie zmieniano.
- Przekazany wynik draft CI na a6: Rust 514 + 3 shutdown, replay/G1/tokenizer 24 + 3
  bez skips, browser 100 z 2 skips; dwie dopuszczone Intel jobs passed, trzy ARM mac
  jobs cancelled z braku runnera. To nie ready-PR full green ani dowód runtime/merge/publication.
  Fallback dotyczy wyłącznie `macos` i `extension`, repo var true; plan nie rozszerza runnerów.
- Source checks: odczyt i wyszukiwanie symboli oraz diff/status dokumentu. Testy,
  build, model, install, network, CI query/dispatch, secret/vault/profile access:
  **NOT_RUN**. Nie czytano held-out JSONL, jego manifestu ani generatora. Bez subagentów.
- Jedyna zmiana: ten plik. Bez implementacji, commit/push, nowych runnerów/usług i R2.

PR https://github.com/wydrox/apassy/pull/104, head a6d0fee1ec87de3bb9560d68d3193610439c7845, draft CI green; experiment UNSUPPORTED(budget), production bouncer unchanged.
