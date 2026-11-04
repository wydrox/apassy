# Review planu dostarczenia bouncera kontekstowego — 2026-11-04

Reviewer: Opus 5.5, source-only, bez subagentów. Branch `feat/bouncer-secret-context`,
HEAD `a6d0fee1ec87de3bb9560d68d3193610439c7845`, PR #104 OPEN DRAFT.
Przedmiot: `docs/design/bouncer-context-delivery-gap-audit-2026-11-04.md` (audyt Sol).

**Stan faktyczny: celu nie dostarczono.** Produkcyjny bouncer jest niezmieniony.
W8 zakończył się `UNSUPPORTED(budget)`, więc B jest UNSUPPORTED, a jakość NOT_RUN.
C, D i E pozostają zablokowane. Nie ma wiarygodnej daty wydania i ten dokument jej nie podaje.

## 1. Werdykt: REVISE

Kierunek audytu jest poprawny: B blokuje budżet compute, a pozostałe etapy są nazwane uczciwie.
Plan wymaga jednak pięciu korekt, zanim stanie się planem roboczym.

**K1. Progi B w etapie 3 są nieaktualne. To poważny błąd.** Audyt przepisał stary próg
supervision §7 („≥90% ordering i ≥30 pp ponad control”). AB-review F1 wykazał, że ten
warunek był pusty z konstrukcji. Recheck zastąpił go nowym warunkiem, a obowiązuje kod
`tools/basemodel/context_eval.py:107-196`. W planie trzeba wpisać ten zestaw bez skrótów:
- facts: ≥150 par counterfactual, ≥90% uporządkowanych (remis liczy się jako błąd),
  żadna strona `must_ask` nie jest dopuszczona. Dodatkowo AUROC(context) − AUROC(control)
  ≥ 0.15 oraz normal rate przy val-τ ≥ control + 15 pp, na porównywalnych wierszach;
- normal: ≥300 wierszy ogółem i ≥50 w każdej z 5 klas obowiązkowych (`cold_start_no_declaration`,
  `known_with_owner_history`, `changed_or_rotated`, `repeat`, `multi_secret`), w każdej
  co najmniej 60% auto-allow;
- risky: ≥300 przypadków i 0 dopuszczonych. Deterministic: ≥100 i 0 dopuszczonych.
  Injection: ≥100 i 0 flipów. Self-reinforcement: 0 flipów. Bramki `label_audit` i
  `available` (0 unavailable wśród mieszczących się wierszy);
- `baseline_shipped`: liczba pytań w żadnej klasie nie może przekroczyć wyniku baseline.
  Rozstrzyga to dowiedziony LB albo H_ship. Stock nigdy nie zastępuje H_ship;
- cost: dla 1 i 3 sekretów p95 ≤ 1.5× baseline oraz RSS ≤ baseline + 256 MiB;
- `gate_b` = quality ∧ baseline ∧ cost. Samo quality PASS niczego nie odblokowuje.

**K2. Decyzja zasobowa pomija `baseline_shipped`.** Nawet udany trening na nowym zasobie
może skończyć się `UNSUPPORTED(shipped_heads_unavailable)`. Stanie się tak, jeśli LB nie
rozstrzygnie bramki, np. po `row_incoherent` z L4 w N2 review. Według AB-review §2.4
H_ship jest tylko w R2. Decyzja właściciela musi więc od razu obejmować odczyt H_ship
(§5). Inaczej opłacony run może nie dać rozstrzygnięcia.

**K3. Etap 5 (D) przedstawia propozycje planu v2 jako wymogi.** Supervision zatwierdziła
tylko A/B (§0). Plan v2 sam zaznacza, że jego poprawki nie przeszły re-review. Dlatego
„14 dni”, „≥30 ocen auto-zgód” i limity retencji to propozycje, które można przeprojektować (§3).

**K4. Etap 2: feature flag „domyślnie OFF” jest zbędny.** Moduł bez wywołania z decyzji
nie potrzebuje przełącznika. Flaga byłaby martwą konfiguracją do późniejszego usunięcia.
W zamian akceptuję wąski pakiet z §4.

**K5. Luka „pełny rekord” jest opisana zbyt literalnie (§2).** Wniosek audytu, że nie
wolno ogłosić usunięcia wszystkich pytań, jest słuszny. Zarzut, że v1 „nie jest rekordem”,
nie trafia jednak w wymaganie użytkownika.

Weryfikacja liczb audytu wobec evidence `41874913253`: zgadzają się. Probe SUCCESS,
`budget.json` `UNSUPPORTED/budget`, `groups=null`, kalibracja 63.8336 s, G800 65477.2066 s
(encoder 9741.6289, head 54943.7074, scoring 791.8703). `summary.json` wymienia jako
anulowane `release-binaries` i dwa ARM macOS test jobs.

## 2. „Pełny rekord”: projekcja zamiast literalnego rekordu

Użytkownik prosił, żeby bouncer korzystał z rekordu, cech i niedawnej historii, a wartości
zostawały w sejfie. Nie prosił o wysyłanie notatek ani nazw do modelu, ani o zniesienie
wszystkich pytań. Trzeba rozróżnić dwie rzeczy:

- **Lokalny builder ma dostęp do rekordu.** `Vault::decision_evidence` czyta jedną spójną
  migawką metadane, deklarację, provenance, origin, use i event. Wymaganie jest spełnione
  co do rodzaju danych.
- **Brain dostaje projekcję semantyczną.** To 17 zamkniętych cech na sekret plus `action`.
  Tytuł, notatki, nazwy pól, custom fields, tekst projektu i event detail są pominięte
  celowo, nie z braku. Przy itemach tworzonych przez agenta to wolny tekst kontrolowany
  przez atakującego (P1-5 krytyki Opusa). Expiry, archive, revoke i Always ask egzekwuje
  lokalnie AccessCheck oraz hard rules, a nie model.

Realne braki projekcji, które mają znaczenie dla decyzji. Żaden nie wymaga teraz zmiany
kontraktu:

| Brak | Wpływ | Kierunek | Postępowanie |
| --- | --- | --- | --- |
| Item **bez deklaracji** ma `env=unknown`, bo builder nie uruchamia detektora wartości (supervision rev. 4) | Właśnie główny ból (MissingDeclaration) zniknie tylko dla czystych odczytów. Change/deploy dalej pytają | więcej pytań, bezpiecznie | Słownik już zawiera `env_from=signal`. Później potrzebny osobno reviewowany *producent* zamkniętej cechy env (detekcja przy zapisie/rotacji), bez zmiany kontraktu. Poza pierwszą aktywacją |
| Chronologia odmowa → późniejsza zgoda nie jest kodowana: bucket counts dają `conflict=yes` | Po jednej odmowie właściciel jest pytany do 30 dni | więcej pytań, bezpiecznie | Zostawić. Kontrakt v2 (np. ostatnia odpowiedź właściciela) tylko wtedy, gdy shadow D pokaże `conflict` jako główną przyczynę pytań |
| Zakres „same-scope” to agent + projekt + `action` (4 klasy) + hosty, **bez rodziny komendy**, choć plan v2 §5.2 ją wymieniał | Np. 2 zgody na dowolne `delete` w projekcie spełniają warunek rubryki dla innego `delete` w dev/staging | możliwa nadgeneralizacja, kierunek fałszywej zgody | Kontraktu nie zmieniać przed B. Raport D wydziela candidate-allow dla `deploy`/`delete` oparte wyłącznie na `owner_allowed`. Pierwsza aktywacja ich nie obejmuje (§3, R3) |
| Historia tylko z tego urządzenia: odmowa na innym Macu daje tu `owner_denied=0` | Dla właściciela z kilkoma Macami `0` nie oznacza braku odmowy | kierunek fałszywej zgody, ale nie gorzej niż dziś: obecna polityka nie używa odmów | Nagłówek `history=local_device` zostaje. Ograniczenie podać wprost w release notes i diagnostyce. Sync użyć jest odłożony |

Wniosek: v1 jest wystarczającą projekcją dla pierwszej aktywacji w zakresie §3. Audyt
przesadził, wymagając zatwierdzenia „listy pól i granicy redakcji” jako osobnego warunku
wstępnego. Tabela powyżej jest tą listą. Nie wolno tylko ogłaszać, że v1 uczy się preferencji
właściciela ani że usuwa wszystkie pytania.

## 3. Krótsza ścieżka krytyczna

**Przyjęte wymogi, nie do skracania:** bramki B z K1; freeze i jedno przejście held-out;
żaden stock w miejscu H_ship; review Opusa przed C; wszystkie hard rules z macierzy kontraktu;
każde unavailable, timeout, overflow, storage error lub brak agenta kończy się pytaniem;
access refusal pozostaje odmową; obecny tor zostaje jako rollback przez jedno wydanie;
release sześciu komponentów zgodnie z AGENTS.md.

**Przeprojektowanie propozycji v2 dla D, z uzasadnieniem:**

- **R1. Bez 14-dniowego minimum kalendarzowego.** Kalendarz nie chroni przed fałszywą zgodą.
  Chronią liczebności. Shadow kończy się, gdy są spełnione liczby z planu: ≥100 odpowiedzi
  właściciela ze zgodnym snapshotem i ≥30 rodzin.
- **R2. Bez bramki „≥30 ocen dawnych auto-zgód”.** Nowe ryzyko powstaje tylko tam, gdzie
  kandydat zezwala, a obecna polityka pyta. Te wiersze w shadow dostają prawdziwą etykietę,
  bo właściciel i tak odpowiada. Wiersze, które obie ścieżki dopuszczają, nie zwiększają
  ryzyka względem dzisiejszego produktu. Ich ocena służy jakości bezwzględnej i może zostać
  opcjonalną funkcją UI. **Ochrona przed fałszywą zgodą** to twardy warunek: 0 Deny właściciela
  na wierszach, które kandydat by dopuścił. Dismiss i timeout nie liczą się jako potwierdzenie
  i są raportowane osobno.
- **R3. Węższa pierwsza aktywacja.** Kandydat może sam dopuścić tylko `read` i `change`.
  `deploy` i `delete` zostają na obecnym torze. Rubryka i tak pyta przy env unknown/production
  dla innych akcji niż `read`, więc koszt produktowy jest mały. Za to D potrzebuje dowodów
  tylko dla częstych klas, a brak rodziny komendy (§2) nie ma skutków.
- **R4. C i D w jednym wydaniu.** Snapshot, lokalny shadow i kod aktywacji trafiają do jednego
  wydania, z aktywacją wyłączoną. Włączenie to jawna, lokalna decyzja właściciela na urządzeniu,
  dostępna dopiero wtedy, gdy lokalny raport spełnia R1 i R2. Agent nie czyta danych właściciela.
  E (usunięcie formularza MissingDeclaration) trafia do następnego wydania. Oszczędza to jedno
  pełne wydanie sześciu komponentów między shadow a aktywacją.

Retencja 10 000/2 000/64 MiB pozostaje propozycją do pomiaru w C, bez nowego procesu.

Ścieżka po korekcie: decyzja właściciela (§5) → B2: calibration probe i najwyżej jeden full
z held-out → review Opusa → C+D w jednym wydaniu (shadow, potem lokalne włączenie) → E w
następnym wydaniu. Pakiet z §4 idzie równolegle i skraca C.

## 4. Pakiet implementacji do rozpoczęcia teraz: uśpiony adapter run → context input

**Akceptuję** go jako wąską zmianę ograniczenia A/B (supervision §0). Jego wartość: przenosi
poza ścieżkę krytyczną budowę wejścia z bieżącego run, czyli per-item project/host fit,
zapytanie evidence i mapowanie odmów. Domyka też trzy pułapki semantyczne zapisane niżej.
Nie zmienia wykonania, nie odblokowuje C i nie zmienia daty.

**Odrzucam teraz:** route `/v1/context-evaluate`, `context_contracts` w health i ładowanie
głów w `serve.py`/`app.py`. Bez wytrenowanych głów route mógłby tylko odmawiać (supervision
rev. 5), a zmienia serwer obecnego braina. Odrzucam też feature flag, call-site w
`run_inner`/`route`/`decide_routed`, shadow, migrację i snapshot. To wszystko należy do C po B PASS.

**API (zamrożone w briefie, żeby oba zadania szły równolegle):**

```rust
// src/broker/context_adapter.rs
pub struct RunItem<'a> {
    pub item_id: u64,
    pub declaration: Option<&'a Declaration>,
    pub known_hosts: &'a [String], // ItemFacts.known_hosts computed by the caller (run.rs in C)
}
pub struct RunContext<'a> {
    pub request: &'a BouncerRequest, // exactly the sanitized request passed to BouncerClient::evaluate
    pub action: ActionKind,
    pub project: Option<&'a Project>,
    pub project_key: &'a str,
    pub agent_id: Option<u64>,
    pub hosts: &'a [String],          // normalized destinations of this run
    pub items: &'a [RunItem<'a>],     // request order
    pub now: u64,
}
pub enum ContextAsk { NoSecrets, TooManySecrets(usize), OverBudget { bound: u32, room: u32 },
                      MissingAgent, DuplicateItem, Storage }
pub fn item_run_match(item: &RunItem<'_>, project: Option<&Project>, hosts: &[String]) -> ItemRunMatch;
pub fn context_input(vault: &Vault, run: &RunContext<'_>) -> Result<ContextInput, ContextAsk>;
```

Semantyka:
- brak deklaracji albo pusty projekt daje `Undeclared`;
- nazwany projekt bez bieżącego projektu daje **`Other`**. Pułapka: `foreign_project` zwraca
  wtedy `None`;
- brak hostów docelowych daje `None`. Hosty pokryte przez **własne** `known_hosts` itemu
  według `host_matches` dają `Known`, w pozostałych przypadkach `Unknown`;
- `agent_id=None` daje `MissingAgent`. Decyzja supervisora: Ask;
- każdy `VaultError` daje `Storage`. Nigdy nie zwracamy częściowego wejścia;
- zero, ponad 3 sekrety i przekroczenie budżetu mapują `ContextRefusal`;
- `known_hosts` dostarcza wołający, bo adapter nie może duplikować `push_item`.

**Zadanie Sol-1 (implementacja):**

| | Ścieżki |
| --- | --- |
| Dozwolone | NOWY `src/broker/context_adapter.rs` (z inline `#[cfg(test)]` dla `item_run_match`); `src/broker/mod.rs`: jedna linia `pub mod context_adapter;`; `src/broker/run.rs`: **wyłącznie** `fn host_matches` → `pub(super) fn host_matches` |
| Zabronione | każda inna linia `run.rs`; `bouncer.rs`, `shadow.rs`, `decide.rs`, `finetune.rs`, `learning.rs`, `patterns.rs`, `calibration.rs`; `src/vault/**`; `tools/**`; kontrakt, hash i fixtures; `Cargo.toml`/`Cargo.lock`; `.github/**`; desktop, iOS, extension, relay; held-out |

**Zadanie Sol-2 (testy, równolegle, z zamrożonego API):**

| | Ścieżki |
| --- | --- |
| Dozwolone | NOWY `tests/context_adapter.rs` |
| Rodzic | linia `mod context_adapter;` w `tests/it.rs` (integration decision 5) |
| Zabronione | wszystko poza tym plikiem |

Sol-2 testuje na tymczasowym sejfie i syntetycznych danych:
- (a) bajtowa zgodność `model_text` z ≥3 golden fixtures `serializer/` dającymi się odtworzyć
  stanem sejfu (np. `owner`, `legacy`, `three`);
- (b) kanarki w wartości, tytule, notatce, nazwie custom field, tekście projektu, nazwie agenta,
  `item_use.command_summary`/`project_label`, `item_event.detail` i hostach. Żaden nie występuje
  w `model_text`, w `{:?}` wejścia ani w błędach;
- (c) wszystkie warianty `ContextAsk`, w tym `four` → `TooManySecrets(4)` i `long-request` → `OverBudget`;
- (d) tabela fit z pułapką „nazwany projekt bez projektu”. Hosty itemu B nie pokrywają itemu A.
  Działa `*.domain`;
- (e) determinizm: dwa wywołania dają identyczne bajty.

**Odbiór (sprawdzalny, wyłącznie z CI):**
1. `git diff --stat` od a6 obejmuje tylko 5 ścieżek. Diff `run.rs` ma dokładnie 1 linię `-`/`+`.
2. `rg -n context_adapter src` znajduje tylko plik modułu i `mod.rs`, bez wywołującego.
   Bez zmian w `tools/basemodel/contracts`, `tests/fixtures`, `Cargo.*`.
3. Draft CI na nowym exact SHA jest zielony. Log nextest pokazuje nowe testy jako wykonane,
   nie skipped. Lokalnie nie budujemy Rusta (próg dysku).
4. Krótka review Opusa tylko tego diffu. Rodzic dopisuje R9 w integration-decisions.
   Bez dispatchu eksperymentu, treningu, held-out, sejfu i profilu.

## 5. Najbliższa decyzja właściciela

Obecne upoważnienie obejmuje plan, review i pakiet z §4. Nowa próba modelowa wymaga
osobnego, wyraźnego „tak” właściciela.

**Pytanie do właściciela (jedno):** „Czy zgadzasz się na jeden nowy eksperyment B2 (nie retry W8)
na wskazanym przez rodzica zasobie o parametrach poniżej, z jednorazowym odczytem shipped heads
z R2 bez ich publikacji?”

Parametry wynikają z estymat a6, nie z pomiarów pełnego treningu. Trening głów to 84%
projekcji, czyli FP32 batch32 × seq512 na 2 wątkach (22.74 s na krok).

| Parametr | Minimum |
| --- | --- |
| Przepustowość względem `ubuntu-24.04` (2 wątki) dla G400 | ≥ 4.5× (per-head: 24 189 / 5 400). Total: ≥ 3.9× |
| Przepustowość dla G800 | ≥ 9.0× per-head (48 378 / 5 400). Total: ≥ 7.9× |
| Alternatywa: ta sama prędkość z dłuższym limitem czasu | ≥ 6.7 h na głowę i ≥ 11.8 h łącznie (G400). Przekracza publiczny 6-godzinny limit joba GitHub-hosted (nie sprawdzano w tym review), więc nie zmieści się w jednym hosted jobie |
| Pamięć i dysk | RSS inference ≈ 3.0 GB (zmierzony). RSS treningu NIE ZMIERZONY. Cache ≤ 6 GiB (limit), wagi bazowe 842 MB |
| Dane i sieć | tylko syntetyczne G1/H1 i publiczne wagi pod pinem. Opcjonalnie odczyt R2 istniejącym sekretem w jobie dispatch-only: weryfikacja `832249…`, bez uploadu (AB-review §2.4 opcja b) |
| Próby | 1 calibration probe tą samą metodą (batch8×4/spot32, margines 1.3, te same 400–800 grup i 4 epoki) oraz najwyżej 1 full z 1 przejściem held-out, na jednym SHA |
| Reguła limitu | właściciel zatwierdza limit czasu/RAM/kosztu **przed** probe. Wynik inny niż ELIGIBLE wobec tego limitu kończy B2, bez zmiany limitu i bez retry |

Czego nadal nie wiemy: rzeczywistego przyspieszenia na jakimkolwiek kandydacie (rozstrzyga
dopiero probe na nim), RSS treningu, ceny, dostępności i zgodności z budżetami, czy quality
przejdzie (FAIL po wydaniu compute jest możliwy), czy LB rozstrzygnie baseline bez H_ship.
Istniejące devboxy mają 8 vCPU. Proporcjonalnie do liczby wątków to najwyżej ~4×, czyli
prawdopodobnie poniżej progu 4.5× dla G400. Nie jest to pomiar.

Rodzic może teraz, read-only, ustalić konkretnego wykonawcę, cenę i dostępność, a potem
przedstawić właścicielowi jeden konkretny run do zgody. Ten review nie autoryzuje runu,
usług, runnerów, sekretów ani wyższych limitów. Jeśli właściciel odmówi, B pozostaje
UNSUPPORTED, a produkcyjny bouncer bez zmian.

Informacyjnie: cost-probe na stock heads dał context p95 953 ms wobec 2 121 ms (1 sekret)
i 1 747 ms wobec 1 835 ms (3 sekrety), RSS ±2 MB. Na walidacji 2 z 11 widoków z 3 sekretami
przekroczyły budżet. To ryzyko dla klasy `multi_secret`, a nie dowód bramki cost.

## 6. Wydanie

Brak daty. Wydanie wymaga B PASS, C+D i E oraz jednej nowej wersji wszystkich sześciu
komponentów (iOS, macOS, Linux CLI, extension, relay, website), z osobnym odbiorem każdego
kanału według AGENTS.md. Ten review niczego nie publikuje.

## Wykonane sprawdzenia i NOT_RUN

- Źródła: przeczytany audyt, supervision §0/§7/§8, plan v2, integration-decisions R1–R8,
  kontrakt v1 oraz reviews AB, recheck, N2-budget, calibration-method, single-probe i
  timeout-analysis. W kodzie: `context_eval.gates`, `CLASSES`, JSON kontraktu,
  `ItemDecisionEvidence`/`EvidenceQuery`, `ActionKind`, `secret_facts` (`ItemRunMatch`,
  `build_input`), widoczność `run::host_matches` (prywatna) i `run::foreign_project`
  (`pub(super)`, `None` bez projektu), `ItemFacts.known_hosts`.
- Evidence G1 `41874913253`: przeczytane `budget.json`, `summary.json`, `receipt.json`,
  `training-report.json` i `cost-probe.json`. Przeliczone L1 i total dla G400/G800.
  Weryfikacji hashy nie powtarzano.
- Nie czytano held-out JSONL, manifestu ani generatora, ani `design/reviews/`.
- NOT_RUN: testy, buildy, modele, instalacje, CI query/dispatch, sieć, sekrety, sejf, profil.
- Jedyny zmieniony plik: ten. Bez commit i push.

PR https://github.com/wydrox/apassy/pull/104, head a6d0fee1ec87de3bb9560d68d3193610439c7845, draft CI green; B UNSUPPORTED(budget), production bouncer unchanged.
