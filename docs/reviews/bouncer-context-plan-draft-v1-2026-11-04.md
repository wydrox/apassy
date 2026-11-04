# Plan implementacji bouncera opartego na cechach i historii sekretu

Data: 2026-11-04. Status: propozycja do krytyki Opusa; nie jest zgodą na wdrożenie zmian polityki.
Baza audytu: origin/main, commit `773f02c2aff5456354776f9ef0bb60e4161800e1` (0.5.18, schema sejfu 34).
Zakres bieżącego zadania: dokument i niezależna krytyka. Bez zmiany działania aplikacji, dostępu do rzeczywistych sekretów, treningu na danych właściciela ani publikacji.

## 1. Wynik dla użytkownika

Użytkownik dodaje sekret i pozwala agentowi pracować. Apassy ocenia bieżącą operację na podstawie cech sekretu, dostępnej historii oraz zadania użytkownika. Nie wymaga wcześniejszego wypełnienia deklaracji ani nauki osobnego zestawu reguł.

Sekret rozwija się przez historię zdarzeń. Brain rozwija się przez post-training głów modelu. Każda decyzja ma zapisany kontekst i pochodzenie informacji.

„Sekret” oznacza tutaj wpis w sejfie. Jego tajna wartość jest odrębnym obiektem: hasło, token, klucz prywatny, seed OTP lub tajne pole nigdy nie staje się wejściem braina, historii modelowej ani treningu. Nie wysyłamy także prefiksu, fragmentu, skrótu wartości ani jej odwracalnego kodowania. Lokalny detektor może przekazać zamkniętą cechę, np. provider=stripe i environment_signal=test, z oznaczeniem źródła.

Metafora „blockchain sekretów” oznacza powiązanie stanu, wersji i zdarzeń z ich pochodzeniem. Ten zakres nie dodaje konsensusu, publicznego łańcucha ani obietnicy kryptograficznej niezmienności istniejącej historii.

## 2. Co już istnieje i gdzie jest rozbieżność

Wskazania poniżej odnoszą się do commitu bazowego, nie do starego lokalnego main.

| Obszar | Stan źródeł | Wniosek |
| --- | --- | --- |
| Wejście modelu | src/broker/bouncer.rs:87–104 i 959–978; src/broker/run.rs:1284–1310 | Do serializowanego stanu trafiają task, command, purpose i opcjonalny owner rule. Brak sekretów jako obiektów i ich historii; normalny run ustawia pustą instruction. |
| Cechy sekretu | src/vault/types.rs:80–125; src/vault/agents.rs:432–440; src/vault/policy.rs:14–55 | Są metadane, rewizje i źródła Owner/Signal/Usage/Default. Można je wykorzystać bez eksportu tajnych pól. |
| Zmiany | src/vault/history.rs:21–29,55–59 | item_event ma czas, rodzaj, opis; limit 200 zdarzeń. Brak kompletnego dawnego stanu, rewizji oraz aktora w każdym zdarzeniu. |
| Użycia | src/vault/usage.rs:103–139 | Są agent, projekt, akcja, hosty, outcome, deciding actor i powiązanie z decyzją. Zezwolenie/użycie nie dowodzi sukcesu operacji u providera. |
| Decyzje | src/vault/learning.rs:261–323 | Są deklaracje, command, task, flags i odpowiedzi braina. Brak dokładnego, wersjonowanego snapshotu wejścia modelu. |
| Ewolucja cech | src/broker/corrections.rs:3–36 | Są już propozycje korekt na podstawie użycia. Nowy mechanizm powinien wykorzystać dowody, bez kolejnego obowiązkowego inboxu konfiguracji. |
| Post-training | src/broker/finetune.rs:253–268,324–335 | Odtwarza wąskie wejście. Owner allow/deny jest zwykle mapowane na task_match, choć przyczyna może dotyczyć sekretu. |
| Rozmiar wejścia | tools/basemodel/serve.py:112–129 | Serwer kontroluje dokładny tokenizer; domyślny limit 512 tokenów obejmuje także pytanie. Duża historia nie zmieści się przez samo dodanie pola. |
| Sync | src/vault/merge.rs:65–122 | Cechy i część historii zmian syncują się; item_use, decision_log, owner_answer i modele są lokalne. Nie można udawać kompletnej historii wszystkich urządzeń. |

Powstaje jeden model kontekstu, wykorzystujący obecne magazyny danych. Nie budujemy równoległego sejfu ani drugiego systemu logowania.

## 3. Docelowa ścieżka decyzji

1. Lokalna kontrola tożsamości, bieżącego dostępu, jawnych ograniczeń właściciela oraz możliwości bezpiecznego wykonania.
2. Zbudowanie jednego kontekstu dla żądania i wszystkich wybranych sekretów, z migawką ich wersji i granicą dostępnej historii.
3. Jedna ocena kontekstu przez aktywne głowy braina; opcjonalny kandydat liczy się w shadow na identycznym wejściu.
4. Lokalna decyzja wykonaj/pytaj, a przy naruszeniu jawnego zakazu odmów. Niedostępna lub niekompletna ocena zawsze pyta.
5. Po odpowiedzi właściciela ponowna kontrola aktualnego upoważnienia i wersji przed wydaniem sekretu do dozwolonego wykonania.
6. Zapis decyzji i późniejszych znanych zdarzeń wykonania. Osobny proces przygotowuje dane do treningu głów.

Właściciel widzi Allow, Dismiss i opcjonalny komentarz. Pytanie wyjaśnia konkretną niepewność bieżącego użycia. Odpowiedź staje się zdarzeniem i etykietą, a nie cichym nadaniem stałego dostępu lub zmianą środowiska.

### 3.1 Co pozostaje kontrolą lokalną

- Uwierzytelniony agent/urządzenie/sesja, odblokowany sejf, bieżący i niewycofany dostęp do wskazanych sekretów.
- Jawne Never, Always ask, zakres Only these items, wygaśnięcie, limity oraz zapisane przez właściciela ograniczenia użycia.
- Ważność konkretnej odpowiedzi właściciela, binding wybranego pola i polecenia, rewizje oraz ponowna kontrola przed wykonaniem.
- Izolacja tajnych wartości, egzekwowane ograniczenia celu/dostawy i poprawność protokołu. Model nie poszerza upoważnienia ani nie naprawia nieważnego podpisu.
- Odpowiedź właściciela dotyczy dokładnie pokazanej operacji; brak odpowiedzi, lock i anulowanie niczego nie zatwierdzają.

Wielość sygnałów ryzyka nie jest tym samym co lista jawnych ograniczeń. Brak projektu w metadanych albo nazwa programu nie może automatycznie tworzyć trwałego zakazu.

### 3.2 Co ma być dowodem dla braina

- Brak deklaracji, brak historii, nieznane środowisko, niepewne uprawnienia oraz sprzeczne sygnały.
- Produkcyjny charakter sekretu, rodzaj operacji, rozpoznane efekty i ryzyko komendy.
- Podobieństwo do wcześniejszych użyć i jawnych odpowiedzi, nowe hosty, nowy agent/projekt oraz niedawna rotacja.
- Reguły heurystycznego analizatora poleceń jako opis ryzyka z pochodzeniem, zamiast ogólnej zasady „dowolna flaga = bez modelu”.

Jawny zakaz właściciela i technicznie wykryta próba ujawnienia tajnej wartości pozostają egzekwowane lokalnie. Błąd heurystyki secret_output trzeba odróżnić od rzeczywistego wykrycia wartości, a nie usunąć cały mechanizm ochrony.

### 3.3 Zmiany polityki wymagające osobnego wskazania w ADR

Włączenie nowej ścieżki zmienia wcześniejsze decyzje ADR 0008, 0009 i 0031. ADR wdrożeniowy musi zawierać macierz stara/nowa semantyka:

| Mechanizm | Docelowa semantyka |
| --- | --- |
| MissingDeclaration jako blokada | Usunięty; brak jest jawnie reprezentowaną informacją wejściową. |
| Default production/admin jako domniemany fakt | Nieznana cecha z ostrożnym priorem, bez udawania potwierdzonej klasyfikacji. |
| Każde produkcyjne write/admin automatycznie pyta | Propozycja zmiany: ryzyko ocenia brain, chyba że właściciel wymaga osobnej zgody. To realne rozszerzenie autonomii względem decyzji z 2026-11-02; nie wolno wprowadzić go jako ukrytej migracji. |
| Wzorzec po 3 zatwierdzeniach omija model | Historyczny dowód z liczbą i źródłem zatwierdzeń; bez automatycznego obejścia modelu. |
| Ręczna kalibracja task_match | Jedna wersjonowana polityka decyzji i kalibracja modelu w procesie walidacji; bez osobnego pokrętła dla użytkownika. |
| Zapamiętana zgoda właściciela | Zachowany jawnie nadany zakres; nie rozszerzamy ani nie unieważniamy go po cichu. Dopasowanie i wykorzystanie są widoczne w kontekście. |
| Cloud agent zawsze pyta | Zachowane w pierwszym zakresie: brak zweryfikowanego zadania i szersze granice zaufania wymagają oddzielnej decyzji. |
| Kody OTP, passkeys, browser fill, connector | Zachowane odrębne upoważnienia i ochrona wartości. Pierwszy zakres dotyczy process run; ich przebudowa nie jest skutkiem ubocznym. |

Plan proponuje docelową architekturę. Samo zatwierdzenie dokumentu planu nie migruje produkcyjnych uprawnień i nie odwołuje wcześniejszych jawnych ograniczeń właściciela.

## 4. Jeden wersjonowany kontekst

Proponowane nazwy kodu: DecisionContextV1, SecretContextV1, DecisionSnapshotV1. Nie mylić ze starym bouncer::DecisionContext: w jednostce A trzeba rozdzielić nazwy i odpowiedzialności.

### 4.1 Zakres danych

DecisionContextV1 zawiera:

- contract_version, serializer_version, question_set_version i history_policy_version;
- bieżący request: oryginalne żądanie użytkownika, źródło i stopień zweryfikowania, purpose agenta, strukturę polecenia, katalog względem projektu, żądaną akcję oraz wykryte cele;
- tablicę wszystkich sekretów: request-local referencję, rewizję, typ/provider, jawne pola i nazwy pól, znane cechy środowiska/uprawnień/projektu/hostów;
- dla każdej cechy wartość albo unknown, źródło, obserwację w czasie, wersję ekstraktora oraz informację, czy jest jawnie potwierdzona; nie wymyślamy numerycznej pewności starego źródła;
- skuteczne ograniczenia właściciela oraz dowody ich pochodzenia;
- ostatnie istotne zmiany, użycia i odpowiedzi wraz z czasem, źródłem decyzji i wersją sekretu, gdy jest znana;
- starsze agregaty, zakres dostępnej historii, urządzenie źródłowe, cutoff i znaczniki omitted/incomplete.

Wielosekretowy request jest oceniany wspólnie. Model musi widzieć, do którego sekretu należy cecha lub zdarzenie. Opinia o jednym sekrecie nie rozciąga się na pozostałe.

Pełny rekord oznacza pełny model cech sekretu, nie surowy zrzut wszystkich pól. Pole tajne nigdy nie jest serializowalne w tym DTO. Pola tekstowe, które mogą zawierać wklejone wartości, przechodzą maskowanie przed snapshotem, budżetowaniem, HTTP i treningiem. Nazwy, notatki, komendy i historia są danymi o oznaczonym źródle, nigdy instrukcjami systemowymi.

### 4.2 Tożsamość i bezpieczny tekst

Lokalny rekord audytowy wiąże item UUID, rewizję, request ID, aktora i zdarzenia. Model dostaje stabilne wyłącznie w obrębie żądania referencje secret_1, secret_2. Pełne ścieżki, lokalne identyfikatory i identyfikatory kont nie są potrzebne do przenoszenia powiązań.

Nie zakładamy, że każdy tekst nietajnego pola jest bezpieczny. Nowy builder dostaje już filtrowane DTO, a nie SecretValue ani dostęp do arbitralnych pól sejfu. Lokalny ekstraktor nie przyjmuje poleceń z historii i nie wykonuje żądań sieciowych, by „sprawdzić klucz”.

### 4.3 Historia i budżet

Proponowana pierwsza polityka: ostatnie 30 dni jako szczegółowe okno, najnowsze 20 istotnych zdarzeń na sekret jako limit kandydatów. To wartości konfiguracyjne implementacji, wymagające pomiaru w jednostce C; nie ustawienia użytkownika ani obietnica, że 20 zdarzeń zmieści się w modelu.

Priorytet zachowania: aktualne jawne ograniczenia i bieżące żądanie w całości, najnowsza rotacja/zmiana dostępu, odmowy właściciela i sprzeczne obserwacje, następnie reprezentatywne użycia. Wiele automatycznych zgód nie może wyprzeć jednej istotnej odmowy. Starsze jawne ograniczenia nie wygasają razem z oknem historii.

Agregaty rozdzielają owner allow, owner deny, model allow, unanswered, execution started, exit status i faktycznie potwierdzony efekt, jeśli istnieje taki dowód. Nie zamieniamy „Allow” w „udane, bezpieczne użycie u providera”.

Serializer jest deterministyczny. Budżet liczy dokładny tokenizer i pełny format każdego pytania, identycznie w inference i treningu. Kompaktowanie ma ustaloną kolejność i zapisuje pominięcia. Nie stosujemy generowanego przez LLM streszczenia, które mogłoby zmienić fakty.

Jeśli sam niezbędny request lub ograniczenia nie mieszczą się w sprawdzonym budżecie, wynik to context_unavailable i pytanie. Nie obcinamy końca polecenia. Zwiększenie limitu modelu wymaga pomiaru pamięci, latencji i ponownej walidacji; samo podniesienie stałej nie jest rozwiązaniem.

### 4.4 Snapshot przed decyzją i współbieżność

Builder czyta cechy i widoczną historię w jednej spójnej transakcji sejfu. Granicą jest monotoniczny lokalny numer obserwacji/zdarzenia, nie tylko czas ścienny; zdarzenie z przyszłości ani później zsynchronizowana informacja nie może wejść do historycznego snapshotu.

Zapisujemy dokładny oczyszczony kontekst oceniony przez model, manifest wersji, model/head hash i cutoff. Snapshot jest niezmienny po rozstrzygnięciu; outcome i odpowiedź właściciela są osobnymi rekordami.

Po oczekiwaniu na model albo właściciela sprawdzamy ponownie upoważnienie, rewizje, binding i ograniczenia. Zmiana sekretu lub ograniczeń unieważnia ocenę. Nowe zdarzenie istotne dla ryzyka, np. cofnięcie dostępu lub odmowa właściciela, również wymaga nowej oceny. Współbieżna automatyczna zgoda nie powinna powodować nieskończonego cyklu unieważnień; wersja istotnego stanu jest odrębna od licznika każdej telemetrii.

## 5. Historia, migracja i wiele urządzeń

Pierwsza wersja wykorzystuje item_event, item_use i decision_log przez jeden interfejs odczytu, dokładając niezbędne powiązania i snapshoty. Nie przenosimy wszystkich starych tabel do nowego ogólnego event store w tym samym wdrożeniu.

- Nowe zdarzenia mają własny identyfikator, obserwowany numer lokalny, referencję sekretu i rewizję, czas, rodzaj, źródło/aktora, powiązanie z decyzją oraz dozwolony payload bez wartości.
- Edycja/rotacja/dostęp/odpowiedź właściciela mają precyzyjne rodzaje; widok bieżących cech jest projekcją danych i dowodów.
- Stare wpisy oznaczamy legacy. Brak rewizji, aktora albo efektu to unknown; nie uzupełniamy ich obecnym stanem i nie udajemy pełnego replay.
- Obecne deklaracje i potwierdzenia zachowujemy jako istniejące cechy z pochodzeniem. Brak deklaracji nie wymaga backfillu na fikcyjne dev lub owner-confirmed.
- Nowe tabele są lokalne tak jak decision_log i item_use. Nie rozszerzamy protokołu sync ani relay o użycia w pierwszym zakresie. Model widzi history_coverage=local_device z lokalnym początkiem obserwacji.
- Zmiany sekretu obserwowane z sync tworzą lokalny fakt observed_remote_change z numerem obserwacji. Nie pożyczamy zaufania do aktywności innego, nieobserwowanego urządzenia.
- Schemat otrzymuje następny wolny numer po aktualnym main w momencie implementacji. Schema 34 jest bazą audytu; nie rezerwujemy teraz 35, bo inne prace mogą go użyć.
- Retencja: snapshoty są w zaszyfrowanym sejfie; mają limity liczby i bajtów, usuwają się razem z decyzjami, a aktywny zapis treningowy posiada manifest danych, które zachowuje. Jednostka B ma ustalić liczby i strategię vacuum na podstawie ograniczonego pomiaru rozmiaru; bez nielimitowanego append.
- Minimalne dane po usunięciu szczegółów: jawny zakres pokrycia, metadane wersji i beztekstowe agregaty. Nie obiecujemy odtworzenia wejścia, którego nie zachowano.
- Kopia starszej aplikacji nie ma czytać nowszego schematu przez obejście wersji. Rollback kodu wymaga wersji kompatybilnej ze schematem albo backupu sprzed migracji; rutynowe wyłączenie polityki nie cofa migracji bazy.

## 6. Głowy modelu i uczenie

Nowy kontekst jest zmianą semantyki wejścia. Istniejące głowy nie są automatycznie uznane za zgodne, mimo identycznego formatu pliku safetensors.

Manifest modelu ma pinować co najmniej bazowy encoder/tokenizer, context contract, serializer, zestaw pytań, history policy i politykę decyzji. Niezgodność daje czytelną niedostępność; nie cofamy po cichu do wejścia bez historii.

### 6.1 Co przewidują głowy

Zachowujemy rozdział ocen faktów i preferencji:

- Fakty operacji, np. zapis, usuwanie i ujawnienie, mają swoje etykiety i nie zmieniają prawdy po kliknięciu Allow.
- Ocena bieżącego użycia sekretów w kontekście zadania i historii potrzebuje osobnego celu. Robocza nazwa owner_accepts_use: przewiduje decyzję właściciela dla tej konkretnej sytuacji; nie jest etykietą „operacja obiektywnie bezpieczna”.
- Mapowanie owner deny na task_match=no zostaje usunięte dla nowego kontraktu. Komentarz i przyczyna pozwalają rozróżniać odmowę operacji, użytego sekretu i nieaktualne zadanie; brak komentarza nie blokuje zapisania odpowiedzi.
- Odpowiedzi modelu przekłada jeden lokalny moduł polityki na wykonaj/pytaj. Dokładne progi, kalibracja i ewentualna dodatkowa głowa są wynikiem jednostki D, nie odziedziczonym zestawem wyjątków.
- Poprzedni eksperyment z bezpośrednim allow/ask nie jest dowodem jakości nowej głowy. Jednostka D musi porównać ten wariant z agregacją pytań i może go odrzucić przed zmianą routingu.

### 6.2 Dane i cold start

Na start powstaje wersja kontekstowa głów uczona i oceniana na sztucznych, opisanych przypadkach. Puste historyczne okno jest normalnym przypadkiem tego modelu. Nowy użytkownik nie musi uzbierać 300 własnych decyzji, żeby w ogóle korzystać z nowego wejścia.

Osobisty post-training zachowuje istniejący mechanizm lokalny lub wybranego hosta, kandydatów, hash głów, shadow, promocję właściciela i rollback. Istniejące minimum 300 decyzji/30 odmów pozostaje progiem treningu osobistego do osobnej decyzji; nie zaniżamy go na podstawie samego celu mniejszej liczby pytań.

- Trenujemy na pre-decision snapshotach i rzeczywistych odpowiedziach właściciela.
- Model allow, zapamiętana odpowiedź, timeout i brak reakcji nie są nowymi owner-supervised approvals/denials.
- Automatyczne zdarzenia mogą być wejściową historią z oznaczonym źródłem. Ich liczba nie staje się potwierdzonym prawem dostępu.
- Stare decyzje bez snapshotu są legacy_context_missing: nie rekonstruujemy ich cech z dzisiejszego sekretu. Zachowują wartość audytową; domyślnie nie uczą nowej oceny kontekstowej.
- Podział train/validation/test jest chronologiczny i grupuje wspólne rodziny komend, sekretów oraz scenariuszy. Powiązane warianty nie mogą znaleźć się po obu stronach podziału. Raport osobno pokazuje pierwszy kontakt z nowym sekretem i znany sekret w nowej sytuacji.
- Historia przykładu kończy się przed jego etykietą. Późniejszy komentarz właściciela nie trafia do wejścia ocenianego przykładu.

## 7. Jednostki implementacji

Wspólne pliki mają jednego edytora. Zależności wskazują kolejność integracji, nie pozwolenie na równoległą edycję tej samej sekcji.

### A. Kontrakt, ADR i zamrożony zestaw przypadków

Pliki: nowy ADR po ostatnim zajętym numerze; docs/contracts/secret-decision-context-v1.md; tests/fixtures/secret-decision-context-v1/; tests/bouncer_brain_contract.rs.

- Ustalić DTO, allow-listę cech, reguły tekstu, provenance, trzy rodzaje outcome i kompatybilność.
- Zapisać każdą zmianę semantyki z sekcji 3.3; jawne ograniczenia i źródła mają oddzielne typy.
- Zamrozić przypadki: brak historii/metadanych, rotacja, konflikt, nowe cele, wiele sekretów i nieufna historia.
- Zachować stare kontrakty jako historyczne; wskazać dokładnie, które fragmenty nowy ADR zastępuje.

Odbiór: fixtures nie dopuszczają SecretValue, tajnych pól, fingerprintów wartości ani przypisania cechy jednego sekretu do drugiego. Stary format nie jest błędnie rozpoznawany jako nowy.
Zależy od: niczego. Wynik nie zmienia routingu.

### B. Snapshoty i adapter istniejącej historii

Pliki: nowe src/vault/decision_context.rs i migracja; src/vault/history.rs, usage.rs, learning.rs, policy.rs, mod.rs, types.rs, merge.rs; tests/vault_migration.rs; tests/sync_schema_upgrade.rs.

- Dodać wersjonowany snapshot, cutoff obserwacji, referencje rewizji oraz istotną wersję stanu.
- Udostępnić jeden ograniczony odczyt cech i historii dla zbioru sekretów; indeksy i limity zamiast pełnego skanu sejfu.
- Zapewnić atomowość zapisu kontekstu i decyzji lub jawny stan incomplete po awarii.
- Oznaczyć legacy, lokalny zakres historii, retencję i usuwanie. Nie przepisywać wartości ani praw dostępu.

Odbiór: migracja starego sejfu, sync konfliktu, kopia/restore, rotacja i retencja zachowują prawdziwe pochodzenie; brak wpisów nie tworzy fałszywej historii. Zestaw dużego syntetycznego sejfu ma ograniczony koszt odczytu.
Zależy od: A.

### C. Builder i identyczna serializacja inference/training

Pliki: nowe src/broker/decision_context.rs; src/broker/run.rs, bouncer.rs, finetune.rs; tools/basemodel/serve.py, train.py; tools/finetune/local_train.py; wspólne fixtures Rust/Python.

- Zbudować kontekst wszystkich sekretów pod spójnym odczytem, bez ujawnienia tajnych wartości w DTO.
- Wspólny kanoniczny format oraz wersje; najpierw dane obowiązkowe, potem deterministycznie wybrane zdarzenia.
- Zastosować te same reguły maskowania i pełnego budżetu w live, export, replay i train.
- Zmierzyć minimalne wejście i wejście z historią na bieżącym tokenizerze. Ustalić rzeczywisty obsługiwany budżet przed doborem głów.

Odbiór: byte-for-byte ta sama reprezentacja snapshotu w obu ścieżkach; zgodność tokenizacji na fixtures; kontrolowane context_unavailable; skan syntetycznych kanarków także w błędach, Debug, HTTP i treningu.
Zależy od: A, B.

### D. Głowy kontekstowe, etykiety i ewaluacja offline

Pliki: src/broker/finetune.rs, shadow.rs; src/vault/candidate.rs; tools/basemodel/common.py, train.py, serve.py, manifest.json; tools/finetune/local_train.py; tests/evals/ i docs/evaluation/.

- Dodać kontekstowe cele i wersje kompatybilności, bez reinterpretacji starych wag.
- Przygotować sztuczny zbiór treningowy oraz odrębny zamrożony zbiór walidacyjny/testowy.
- Porównać błędy automatycznej zgody i częstość pytań dla starej polityki oraz nowego kontekstu; wybór progów zakończyć przed oceną zamrożonego testu.
- Raportować wynik per środowisko/akcja/źródło historii/typ sekretu, nie samą ogólną zgodność z właścicielem.
- Kandydat kontekstowy dostaje osobny manifest i może być oceniany obok starego modelu na tej samej operacji, ale z prawidłowo dopasowanym własnym wejściem.

Odbiór: cold start i historyczny kontekst mają dowody działania; zero naruszeń jawnych zakazów w testach; fałszywe zgody i pytania mają podane mianowniki. Brak wystarczających wyników blokuje zmianę polityki, nie blokuje dostarczania B i C.
Zależy od: A, C.

### E. Jedna ścieżka lokalnej decyzji

Pliki: src/broker/run.rs, bouncer.rs, route_diagnostics.rs, learning.rs, calibration.rs, patterns.rs, corrections.rs; tests/bouncer_rules.rs, learning.rs oraz nowe tests/decision_context.rs.

- Rozdzielić kontrolę upoważnienia od kontekstowej oceny ryzyka.
- Usunąć MissingDeclaration i history eligibility jako warunek wejścia do nowej oceny; brak historii jest wspieranym wejściem.
- Zastąpić learned pattern bypass i osobną ręczną kalibrację dowodami oraz jedną polityką.
- Przenieść automatyczne klasyfikacje do cech z pochodzeniem. Nie zamieniać zatwierdzenia operacji w zmianę środowiska.
- Zachować jawnie nadane zakresy i ponowną kontrolę; zmiany produkcyjnej autonomii wyłącznie zgodnie z macierzą nowego ADR.
- Wyeliminować dwie rozbieżne implementacje reguł w route/before_model/replay.

Odbiór: bez deklaracji model jest wywołany; zmiana cech/historii zmienia wejście; dwa różne sekrety przy tej samej komendzie nie zlewają się w jeden przypadek. Stary head nigdy nie rozstrzyga nowej polityki. Revoke/rotacja/istotna odmowa w trakcie oczekiwania unieważniają ocenę.
Zależy od: B, C, D.

### F. Prosty interfejs i diagnostyka

Pliki: src/desktop/ui/decisions.rs, bouncer.rs, bouncer_load.rs, settings.rs; src/desktop/learning_ui.rs; src/cli/commands.rs; src/decision_log.rs. Zmiany iOS tylko po ustaleniu zgodności istniejącej karty pytania.

- Jedno pytanie o operację i opcjonalny komentarz, bez obowiązkowego wyboru dev/prod lub „enable bouncer”.
- Pokazać rozpoznane cechy i ostatnie istotne zdarzenia w szczegółach „Why”, wraz z unknown i niepełną historią.
- Liczniki: admission refusal, model evaluated, model allowed, model asked, owner allowed/denied, no answer, execution result. Każdy licznik opisuje własny etap.
- Dwa różne czasy: czas oceny modelu i czas odpowiedzi właściciela. Nagłówek Denied nie obejmuje timeoutu bez wyjaśnienia.
- Snapshot i command pozostają w zaszyfrowanej historii; płaski log bez sesji ma tylko minimalne zamknięte kategorie i identyfikację kontraktu, bez nowych tekstów i danych historii.

Odbiór: użytkownik nie musi rozumieć „deklaracji”, „calibration” ani „head hash”, żeby używać sekretu. CLI i istniejące odpowiedzi iPhone'a zachowują swoje upoważnienia; starszy klient nie klasyfikuje sekretów jako efekt uboczny.
Zależy od: E; F nie dodaje brakujących zmian polityki.

### G. Przejście na nową wersję i usunięcie starej ścieżki

Pliki: manifesty modelu i migracji; docs/operations/bouncer.md, learning.md, fine-tune.md; docs/security/trust-model.md; odpowiednie kontrakty i workflow testowe.

- Najpierw recording-only kontekstu bez zmiany wykonania, potem porównanie w shadow, potem jawne włączenie nowej polityki w wersji rozwojowej, na końcu wydanie.
- Nowy kandydat jest ładowany i sprawdzany przed przełączeniem; po błędzie aktywacja nie jest częściowa.
- Rollback preferuje ostatni zgodny head/policy. Gdy go nie ma, właściciel odpowiada na operacje; brak automatycznego powrotu do wejścia bez historii z szerszymi uprawnieniami.
- Usunąć produkcyjne użycie pattern/calibration/evaluation-scope bypass po migracji, zachowując kompatybilne odczyty starych zapisów przez zdefiniowane okno. Nie utrzymywać dwóch docelowych architektur.
- Zmiana zakresu danych wysyłanych do zewnętrznego braina wymaga nowej wersji opisu i zgody na hosting. Stara zgoda nie obejmuje automatycznie historii i nowych pól; do tego czasu lokalna ścieżka jest dostępna.
- Release dopiero na jednej nowej wspólnej wersji sześciu komponentów, zgodnie z AGENTS.md. Numer wybiera koordynator wydania; nie publikujemy ponownie 0.5.18.

Odbiór: przełączenie i restart, niezgodny serwer/head, cofnięcie wersji polityki, lock oraz przerwane pobranie modelu mają sprawdzone wyniki. Źródłowy test nie stanowi dowodu publikacji ani działania urządzenia.
Zależy od: E, F i dowodów z sekcji 8.

## 8. Macierz weryfikacji i bramki odbioru

Wszystkie dane testowe są sztuczne. Brak wywołań z rzeczywistymi sekretami, czytania właścicielskiego sejfu i automatycznego odtwarzania poleceń użytkownika.

| Obszar | Minimalne przypadki | Wymagany dowód |
| --- | --- | --- |
| Wartości | API key, hasło, SSH/private key, OTP seed, URL z userinfo, ukryta wartość w notatce i komendzie | Kanarki nie trafiają do model input, snapshotu, eksportu treningowego, błędów ani płaskich logów. |
| Uczenie z historii | identyczna komenda, inne sekrety; identyczny sekret, inna historia; brak historii; model-only approvals | Różne konteksty zachowują rozróżnienie; brak pozornej owner evidence. |
| Czas i rewizje | zmiana przed/po cutoff, późny sync, rotacja, cofnięcie zegara | Reprodukowany snapshot nie zawiera przyszłych faktów; nowe fakty nie uczą dawnej decyzji. |
| Upoważnienie | Never, Always ask, revoke, archived/restored, zawężenie zakresu, zmiana pola lub skryptu | Żadna odpowiedź braina nie omija tych kontroli. |
| Kontekst ryzyka | test/prod, odczyt/zapis, nowy host, obcy projekt, wiele sekretów, shell wrappers | Raport fałszywych zgód i pytań dla każdej klasy oraz porównanie z bazą. |
| Dane nieufne | polecenia w notatkach/historii, instrukcje podszywające się pod owner, agent spamujący allowed events | Pochodzenie nie zmienia się w owner; jawne zakazy i istotne odmowy pozostają obecne w wejściu. |
| Budżet | długi request, wiele sekretów, wiele odmów, maksymalna liczba pól | Ten sam serializer i token budget; przewidywalny fallback bez cichego obcięcia. |
| Kompatybilność | stary eksport/head/serwer, nowy snapshot, stary companion | Brak cichej zmiany semantyki i automatycznego osłabienia dostępu. |
| Wykonanie | zgoda bez startu, start/exit error, provider outcome unknown | Zgoda nie jest zapisana jako potwierdzony sukces. |
| Model | cold start, kontekstowe głowy, shadow failure, rollback | Aktywna decyzja nie korzysta z wyniku kandydata; każdy wynik wiąże manifest i wejście. |

Przed przełączeniem polityki:

- Wszystkie deterministyczne testy upoważnień, kanarków i cutoff przechodzą.
- Zamrożony zbiór obejmuje osobno poprawne operacje i operacje wymagające pytania; klasy i liczebności są opublikowane przed treningiem. Nie przyjmujemy „model działa”, gdy intended inference coverage wynosi zero.
- W klasie jawnie niedozwolonej: zero automatycznych wykonań. W ryzykownych przypadkach bez jawnego zakazu: cel zero fałszywych zgód na zamrożonym zbiorze, z raportem liczebności i ograniczeń takiego wyniku.
- W normalnych przypadkach występują poprawne automatyczne zgody oraz spadek liczby niepotrzebnych pytań względem starego routingu. Wielkość zbioru i docelowy ask rate należy zamknąć w A/D przed testem końcowym; bez tego E nie przechodzi do aktywacji.
- Latencja p50/p95, rozmiar snapshotu i szczyt RAM są zmierzone przy pustej i długiej historii oraz wielu sekretach. Bieżące deadline'y klienta pozostają; nie wydłużamy ich, aby ukryć przepełniony format.
- Native QA sprawdza pytanie, Allow, Dismiss, timeout, lock i urządzenie odpowiadające. Browser/OTP/passkey/provider acceptance pozostają osobnymi dowodami.

Pełne testy Rust i modele uruchamia CI na dokładnym commicie. Lokalne skupione sprawdzenia wyłącznie przez ~/.local/bin/heavy-check; nextest zgodnie z AGENTS.md, doc tests osobno. Bez lokalnego Docker VM, bez produkcyjnego VPS do testów i bez płatnych treningów w ramach tego planu. Lokalne targety po sesji usuwamy dopiero po zatrzymaniu własnych procesów i zachowaniu dowodów.

## 9. Kolejność integracji i prace równoległe

1. A ustala interfejsy i przypadki; reviewer krytykuje kontrakt i macierz polityki.
2. B i szkielety C mogą powstawać równolegle przy oddzielnych plikach; serializer integruje jeden właściciel.
3. C zamyka token budget; D buduje i sprawdza zgodne głowy. UI może przygotować widoki danych na fixtures.
4. E integruje nowy routing po wynikach D; F upraszcza interfejs i diagnostykę.
5. G prowadzi recording/shadow/aktywację i usuwa stary tor po spełnieniu kryteriów.

Nie podajemy czasu wykonania przed pomiarem kontekstu i treningu. Największą niewiadomą jest jakość i budżet nowego wejścia; sam refaktor Rust nie rozwiązuje tej części.

## 10. Co Opus ma zakwestionować

- Czy proponowany zakres rzeczywiście upraszcza produkt i kod, czy jedynie dodaje kolejną warstwę.
- Czy zmiany semantyki produkcji, zapamiętanych zgód, hostów i klasyfikacji są jawne i spójne.
- Czy SecretContextV1 może pośrednio wynieść wartość albo zmanipulować pochodzenie dowodu.
- Czy cold start, budżet 512, osobne głowy i interpretacja owner allow/deny mają wykonalną ścieżkę.
- Czy snapshoty, retencja, sync, rotacja i rollback zachowują prawdziwy stan historyczny.
- Czy kryteria odbioru umożliwiają przyjęcie zawsze-pytającego albo nadmiernie pobłażliwego modelu.
- Co należy usunąć lub odłożyć oraz jaki jest najmniejszy sensowny pierwszy zakres.

Krytyka ma podawać: ważność, konkretny problem, scenariusz awarii, wskazanie sekcji oraz proponowaną zmianę. Pochwała bez szukania kontrprzykładów nie jest recenzją.
