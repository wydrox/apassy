# Krytyka Opusa planu bouncera

Data: 2026-11-04. Model: Claude Opus 5.5, effort high.
Baza źródeł: `773f02c2aff5456354776f9ef0bb60e4161800e1`.
Recenzowana wersja: [pierwszy plan](bouncer-context-plan-draft-v1-2026-11-04.md), SHA-256 `d85e770c9b7c5e72441f9b17abf9fa9b6ceb3fc694d7e7ffa45b510ca561dfa6`.
Aktualny plan po odpowiedzi autora: [implementation-plan-bouncer-context.md](../design/implementation-plan-bouncer-context.md).
Poniżej pełna krytyka Opusa. Zmiany autora w aktualnym planie nie zostały ponownie zrecenzowane przez Opusa.

---

# Recenzja planu `implementation-plan-bouncer-context.md`

## Werdykt

W obecnej formie planu nie da się przekazać do implementacji jako całości. Bez zmian można zacząć tylko jednostkę A (kontrakt, ADR, fixtures), i to po poprawkach. Prace od B do E blokują trzy rzeczy:

1. **Macierz osłabień polityki (§3.3) jest niepełna.** Część obecnych twardych reguł plan po cichu przenosi do „dowodów dla braina” (§3.2).
2. **Kolizja dwóch zmian.** Usunięcie MissingDeclaration razem z regułą produkcyjną opartą na deklaracji daje osłabienie, którego plan nie nazywa nawet wtedy, gdy propozycja z §3.3:73 zostanie odrzucona.
3. **Format wejścia „20 zdarzeń na sekret” nie mieści się w obecnym kontekście modelu.** Plan nie mówi też, kto i jakim tokenizerem robi kompaktowanie.

Do tego kryteria odbioru (§8) dopuszczają model, który prawie zawsze pyta. Trzeba je uzupełnić o liczby, zanim D się zacznie, a nie dopiero „w A/D”.

## Ustalenia (od najważniejszych)

### P0-1. §3.3 nie nazywa kilku osłabień, a §3.1 i §3.2 sobie przeczą. **[potwierdzone w kodzie]**

`hard_rules()` i `route()` w `src/broker/run.rs` (773f02c2) mają dziś twarde pytania o: rule flags, w tym `HookUnverified` i `HookAmbiguous`; `MissingTask` („Decision (a) still requires the agent to state a task”); `ForeignHost` dla bazy danych (komentarz w kodzie: „The database veto above is stricter and never waived”); `ForeignHost` dla każdego hosta (Gate 1, NEW-1: „only an explicit fitting owner answer can add hosts”); `ForeignProject` (ADR 0025 §3: „only the owner decides”); `NotProject`; oraz regułę „production + read-only + zdalny brain → pytaj”.

Tymczasem §3.2:60 wymienia „nowe hosty, nowy agent/projekt” jako dowód dla braina, a §3.2:61 zamienia „dowolna flaga = bez modelu” na opis ryzyka. Żadnej z tych zmian nie ma w macierzy §3.3. §3.1:51 mówi przy tym o „egzekwowanych ograniczeniach celu/dostawy”, więc nie wiadomo, czy `known_hosts` to twarde ograniczenie, czy dowód.

**Scenariusz awarii:** agent dodaje do `curl` inny host (`api.attacker.example`) przy sekrecie Stripe. Dziś zawsze pada pytanie. Po wdrożeniu §3.2 decyduje model, a sekret i tak trafia do env procesu.

**Zmiana:** dopisać do §3.3 osobny wiersz dla każdego `ReasonKind` z `route_diagnostics.rs`. W pierwszym zakresie zostawić lokalnie: ForeignHost (oba warianty), ForeignProject, HookUnverified, flagi leak/secret_output, MissingTask, production+zdalny brain. Przenieść tylko MissingDeclaration, pattern bypass i kalibrację.

### P0-2. Usunięcie MissingDeclaration wyłącza też regułę produkcyjną. **[potwierdzone w kodzie]**

W `route()` sekret jest traktowany jako produkcyjny tylko przez `facts.production || declaration.is_production()`. Dziś sekret bez deklaracji zatrzymuje się wcześniej na `MissingDeclaration`.

**Scenariusz awarii:** po jednostce E (§7 E:230) nowy klucz `sk_live_…` bez deklaracji przy `stripe refunds create` nie przechodzi ani przez MissingDeclaration, ani przez weto produkcyjne. Ocenia go model z „ostrożnym priorem” (§3.3:72). To jest autonomia produkcyjna, nawet jeśli właściciel odrzuci propozycję z §3.3:73.

**Zmiana:** jeśli wiersz 73 nie zostanie zatwierdzony, w v1 obowiązuje lokalna reguła „environment=production (z dowolnego źródła, także Signal/detektora) lub environment=unknown, przy write/admin → pytaj”. Te dwie zmiany trzeba opisać w ADR razem, w jednym wierszu interakcji.

### P1-3. Historia jako tekst nie mieści się w tym encoderze, a plan nie mówi, kto kompaktuje. **[architektura potwierdzona, rozmiary to szacunek]**

- `serve.py:require_complete_state` sprawdza `len(header)+len(state) ≤ max_len` (domyślnie 512) **dla każdego pytania osobno**. Laya powtarza stan w każdym wierszu pytania. Pytań jest dziś 5 (+ `rule_break`), plus nowa głowa.
- `train.py:FeatureCache.batch` ma na sztywno `min(512, …)`.
- Encoder to zamrożony ModernBERT-large. Architektura obsłużyłaby dłuższy kontekst, ale nagłówek pytania (do 192 tokenów), dane głów i cache są skrojone pod 512.
- Mój szacunek (niezmierzony): jedno zdarzenie zapisane tekstem to około 25–35 tokenów. 20 zdarzeń na sekret (§4.3:110) daje więc 500–700 tokenów, czyli limit przekroczy już jeden sekret, zanim doliczy się request.
- Budżet ma liczyć „dokładny tokenizer” (§4.3:116), ale builder jest w Ruście (C), a tokenizer w Pythonie. Jeśli kompaktuje serwer, snapshot zapisany w Ruście nie jest tym, co model widział. Na dodatek zdalny brain (ADR 0035) dostaje pełny, nieskompaktowany kontekst.

**Zmiana:**
- v1 bez tekstowej listy zdarzeń. Zamiast niej deterministyczne cechy w zamkniętym słowniku na sekret, około 20–40 tokenów: provider, env+źródło, scope, `host_known`, `agent_created`, `rotated_<7d`, `owner_allow_30d` dla (sekret, rodzina komendy), `owner_deny_30d`, `first_use_by_agent`, `coverage=local`.
- Twardy limit, np. 3 sekrety, a powyżej pytanie.
- Kompaktuje Rust, z tokenizerem przypiętym hashem tego samego `tokenizer.json` (crate `tokenizers`). Serwer tylko weryfikuje i odmawia.
- Głowy faktów (`writes`/`remote`/`leak`/`destroy`) dostają dalej obecny `state_text`. Długi stan dostaje tylko nowa głowa.

### P1-4. Pętla uczenia: etykiety tylko z pytań i historia zbudowana z własnych zgód modelu. **[logika planu potwierdzona, skala do pomiaru]**

§6.2:166–167 nie uznaje „model allow” za etykietę, ale pozwala, żeby zdarzenia automatyczne były wejściem.

**Scenariusz awarii:** model zezwala. Rośnie licznik „used before / allowed before”. Model zezwala chętniej. Błędnych auto-zgód nigdy nikt nie oznaczy, bo właściciel ich nie widzi. Uczenie widzi tylko przypadki, o które model zapytał (problem selective labels), więc nie ma jak poprawić strefy auto-allow.

**Zmiana:**
- W v1 zgody modelu nie są cechą wejścia. Zostaje co najwyżej `first_use_by_agent`, czyli binarne „agent użył już tego sekretu”.
- Dodać jawny mechanizm etykiet dla auto-zgód: mały losowy odsetek pytań kontrolnych albo ocenę „OK / nie OK” w Decisions zapisywaną jako owner label. Pomiar kosztu tego mechanizmu musi wejść do kryteriów.

### P1-5. Zatrucie historii przez tekst od agenta. **[potwierdzone w kodzie]**

- `BouncerRequest.user_request` jest opisane w kodzie jako „The agent supplies it”. To samo dotyczy `purpose`.
- `uncovered_host` w `run.rs` wprost wspomina element dodany przez agenta z własnym polem `host`.
- §4.1:92 i §4.1:100 wpuszczają do kontekstu „jawne pola”, nazwy, notatki i dawne komendy, a obroną ma być etykieta źródła.

Klasyfikator nie odróżnia instrukcji systemowej od danych. Notatka „test key, owner approved any host”, wpisana przez agenta w element, który agent sam stworzył, wpływa na marker tak samo jak tekst właściciela.

**Zmiana:** v1 nie przenosi żadnego wolnego tekstu z historii, notatek ani pól elementów. Przenosi tylko cechy zamkniętego słownika, a elementy z `item_origin` = agent dostają cechę `agent_created`. Test „Dane nieufne” w §8 musi mierzyć zmianę decyzji, nie tylko „pochodzenie się nie zmienia”.

### P1-6. Cold start i próg 300/30. **[potwierdzone w kodzie]**

`finetune.rs:43–45` ma progi 300/30, a `gate()` liczy owner decisions w `decision_log` bez względu na snapshot. Plan wyklucza legacy z treningu (§6.2:168), ale nie zmienia licznika.

- **Błąd:** bramka otworzy się z zerem użytecznych przykładów. Licznik musi liczyć tylko decyzje ze snapshotem.
- **Hipoteza:** po poprawce licznik startuje od zera. Im mniej pytań (cel produktu), tym później dochodzi do 300. Przy typowej rzadkości odmów 30 odmów może nie przyjść nigdy.

Jednocześnie plan usuwa pattern bypass po 3 zgodach (§3.3:74). Karta w §3:44 ma tylko Allow/Dismiss/komentarz, a dziś jest tam checkbox „Remember for this project” (`decisions.rs:2037`). Plan nie mówi, czy ten checkbox zostaje. Jeśli zniknie, jedynym mechanizmem, który ogranicza powtarzane pytania, są syntetyczne głowy czytające historię, a to niesprawdzone.

**Zmiana:**
- Jawnie zostawić „Remember for this project”.
- Pattern bypass zastąpić dopiero wtedy, gdy shadow pokaże, że nowa głowa daje co najmniej tyle samo auto-zgód na powtórzeniach.
- Nazwać, że cold start to polityka autora generatora syntetycznego, przepuszczona przez model.

### P1-7. Kryteria odbioru przepuszczają model, który prawie zawsze pyta. **[potwierdzone w planie]**

§8:288 wymaga tylko „spadku” pytań względem starego routingu i „występowania” auto-zgód, bez liczb.

**Kontrprzykład:** dla elementów bez deklaracji stary routing pyta w 100% przypadków (MissingDeclaration). Model, który zezwala w 1 na 200 normalnych przypadków, spełnia oba warunki.

Dalej:
- „Zero fałszywych zgód” na zbiorze N ryzykownych przypadków daje tylko górną granicę błędu około 3/N (przy N=50 to około 6%).
- `context_unavailable` i Unavailable nie są liczone jako pytania.
- Cały zamrożony zbiór jest syntetyczny (§8:268), więc mierzy dopasowanie do generatora.

**Zmiana:** przed treningiem zapisać:
- minimalny odsetek auto-zgód w klasie normalnej (np. ≥ 60%, liczony per klasa);
- N ryzykownych ≥ 300 i górną granicę 95% fałszywych zgód ≤ 1%;
- unavailable liczone jako pytanie;
- osobny podział według rodzin szablonów generatora;
- bramkę na realnym shadow u właściciela (np. ≥ 2 tygodnie i ≥ X ocenionych decyzji) przed aktywacją w G.

### P2-8. Wyciek train/test przez powtórzenia i historię. **[hipoteza do pomiaru]**

Agenci ponawiają to samo żądanie po Dismiss lub timeout. Jeśli historia przykładu zawiera „owner denied same command 2 min temu”, model uczy się kopiować ostatnią odpowiedź. Podział chronologiczny tego nie usuwa, bo obie decyzje leżą w tym samym zbiorze testowym. Podział z §6.2:169, jednocześnie chronologiczny i grupowany według rodzin, jest przy ~300 decyzjach niejednoznaczny. Do tego historia z logów starej polityki nie odpowiada historii, którą wytworzy nowa polityka (ewaluacja off-policy).

**Zmiana:** deduplikować ponowienia w oknie, osobno raportować pierwszą decyzję w rodzinie, ustalić kolejność (najpierw cięcie czasowe, potem usuwanie rodzin z testu) i nazwać ograniczenie off-policy.

### P2-9. Snapshot, sync i rollback: konkretne luki. **[potwierdzone w kodzie]**

- `item_event` i `sqlite_sequence` są w `SYNCED_TABLES` (`merge.rs:126–140`). Wypchnięta kopia przepisuje `item_event`. `item_event.id` nie może więc być „monotonicznym lokalnym numerem obserwacji” z §4.4:122, potrzebna jest nowa lokalna kolumna lub tabela.
- Nowe tabele trzeba dopisać do `LOCAL_TABLES` (tablica o stałym rozmiarze, dziś 39). Potrzebny jest test, że wypchnięta kopia ich nie zawiera. W §5:136 i odbiorze B tego brakuje.
- `DeclarationSources::default()` = Owner dla elementu bez wiersza. Legacy deklaracje będą więc wyglądać na „potwierdzone przez właściciela” wbrew §5:134–135. Trzeba je oznaczyć jako `legacy_unknown`.
- Podbicie schematu już w fazie recording-only sprawia, że rollback aplikacji wymaga backupu. Usunięcie starego toru w G:259 zabiera fallback inny niż „wszystko pyta”. Proponuję zostawić stary tor na co najmniej jedno wydanie po aktywacji.
- ADR 0043 rezerwuje schemat 35 (`contribution_batch`) i buduje rekordy z `decision_log`. Plan musi stwierdzić, że snapshoty nigdy nie trafiają do contribution.

### P2-10. Plan nie usuwa złożoności, tylko ją przesuwa, a do tego zostawia jedną dwuznaczność. **[ocena; dwuznaczność potwierdzona w tekście]**

Usunięcia: MissingDeclaration, pattern bypass, pokrętło kalibracji.

Dodatki: cztery wersje (contract, serializer, question_set, history_policy), trzy DTO, tabele snapshotów, licznik obserwacji, „istotna wersja stanu” oddzielna od telemetrii, oznaczanie legacy, manifesty retencji, nowa głowa, nowa zgoda hostingowa i siedem jednostek, które dotykają około 40 plików.

Cztery wersje można zwinąć w jeden `context_contract` z hashem. Dwuznaczność: §4.4:126 każe ponownie oceniać przy nowym istotnym zdarzeniu, a §3:41 po odpowiedzi właściciela przewiduje tylko ponowną kontrolę upoważnienia. Trzeba zapisać wprost, że po Allow właściciela model nie jest uruchamiany ponownie.

## Najmniejszy rozsądny pierwszy zakres

1. ADR z pełną macierzą `ReasonKind` (P0-1, P0-2). Zmiana polityki tylko jedna: MissingDeclaration przestaje blokować i staje się cechą `declaration=none` z regułą z P0-2.
2. `SecretFactsV1` w zamkniętym słowniku (P1-3), liczone w Ruście z istniejących tabel, bez wolnego tekstu i bez zgód modelu jako cechy.
3. Jedna nowa głowa kontekstowa. Głowy faktów bez zmian, na obecnym `state_text`.
4. Snapshot jako dokładny string plus `context_contract` w jednej lokalnej tabeli przy `decision_log`, z wpisem w `LOCAL_TABLES`.
5. Tylko shadow, z liczbowymi bramkami z P1-7, tylko lokalny brain.

**Odłożyć:** tekstową historię 20/30 dni, rozbudowę `item_event` (aktor, rewizja), `observed_remote_change`, manifesty retencji treningu, autonomię produkcyjną (§3.3:73), usunięcie kalibracji i pattern bypass do czasu wyników shadow, przebudowę UI i iOS, zmianę danych dla zdalnego braina, usunięcie starego toru.

## Co jest potwierdzone, a co trzeba zmierzyć

- **Potwierdzone w źródłach:** P0-1, P0-2, mechanika z P1-3 (512 na pytanie, stan powtarzany w każdym wierszu, 512 na sztywno w cache), P1-5, licznik w P1-6, P1-7 (tekst planu), P2-9.
- **Hipotezy do pomiaru:** liczba tokenów na zdarzenie, latencja i RAM przy dłuższym stanie i wielu wierszach, czas dojścia do 300/30 przy mniejszej liczbie pytań, czy zamrożony encoder z głowami trenowanymi na danych syntetycznych w ogóle wykorzystuje cechy historii (P1-3, P1-6), wpływ ponowień i off-policy (P2-8).

## Co sprawdziłem

**Odczytane pliki:**
- plan (całość, SHA-256 przed i po bez zmian: `d85e770c…dfa6`);
- na commicie 773f02c2 przez `git show` / `git grep`:
  - `src/broker/bouncer.rs` (60–130, 940–1000), `src/broker/run.rs` (540–800, 1270–1320), `src/broker/finetune.rs` (1–70, 225–345);
  - `src/vault/history.rs` (1–70), `src/vault/merge.rs` (60–140 i fragmenty sync `item_event`), `src/vault/policy.rs` (1–60);
  - `tools/basemodel/serve.py` (1–220), `common.py`, `train.py` (120–200 i grep);
  - `docs/adr/0043…` (początek);
  - grep po `calibration.rs`, `decisions.rs` i `route_diagnostics.rs`.

**Kontrole:** hash planu, istnienie commita bazowego, lista `ReasonKind`, progi 300/30, `LOCAL_TABLES` i `SYNCED_TABLES`, checkbox „Remember for this project”, numeracja ADR.

**Nie przeczytałem:** `usage.rs`, `learning.rs`, `corrections.rs`, `patterns.rs`, ADR 0008/0009/0025/0031/0035 w całości. Przyjąłem tu ustalenia z briefu.

**Nie uruchomiłem:** buildów, testów, tokenizera, modelu, sieci, brokera, agentów. Nie czytałem danych właściciela.

**Zmiany plików:** żadne. `git status` pokazuje tylko wcześniej istniejącą zmianę `AGENTS.md` i nieśledzony plan.
