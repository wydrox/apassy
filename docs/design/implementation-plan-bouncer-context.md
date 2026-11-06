# Plan implementacji bouncera opartego na cechach i historii sekretu

Data: 2026-11-04. Wersja 2 po krytyce Claude Opus 5.5.
Status: plan do decyzji implementacyjnej; poprawki autora nie przeszły ponownej recenzji Opusa.
Baza źródeł: origin/main `773f02c2aff5456354776f9ef0bb60e4161800e1` (0.5.18, schema sejfu 34).

[Pełna krytyka Opusa](../reviews/bouncer-context-plan-opus-2026-11-04.md).
[Pierwsza recenzowana wersja planu](../reviews/bouncer-context-plan-draft-v1-2026-11-04.md).

## 1. Cel i granice

Sekret jest wpisem w sejfie z cechami, wersją i historią. Brain ocenia bieżące użycie na podstawie tych informacji oraz zadania użytkownika. Sekret rozwija się przez zdarzenia; model przez post-training głów. Użytkownik nie musi najpierw wypełniać „deklaracji”, żeby jego żądanie zostało ocenione.

Hasło, token, API key, klucz prywatny, seed OTP i inne tajne wartości pozostają w sejfie. Nie są wejściem inference, snapshotu ani treningu. Nie wysyłamy też ich fragmentów, fingerprintów ani odwracalnych kodowań. Lokalny detektor może zwrócić zamkniętą cechę, np. provider=stripe i environment=test, wraz ze źródłem.

„Blockchain” oznacza tutaj historię powiązaną ze stanem i wersją sekretu. Nie dodajemy publicznego łańcucha, konsensusu ani obietnicy kryptograficznej niezmienności istniejących logów.

Pierwszy etap jest mniejszy od docelowej przebudowy: lokalny brain, ustrukturyzowane cechy z istniejącej historii, jedna nowa głowa i wyłącznie shadow. Wynik kandydata nie wykonuje poleceń ani nie zmienia dostępu. Nie przebudowujemy od razu wszystkich tabel, UI, iOS i hostingu.

Ten dokument planuje implementację. W ramach jego przygotowania nie zmieniono produktu, nie trenowano modelu i nie odczytywano rzeczywistego sejfu.

## 2. Potwierdzona baza

Wszystkie wskazania dotyczą commita bazowego, nie starego lokalnego main.

| Obszar | Źródło | Znaczenie dla planu |
| --- | --- | --- |
| BouncerRequest i state_text | src/broker/bouncer.rs:87–104,959–978; src/broker/run.rs:1284–1310 | Brain dostaje task, command, purpose i opcjonalny rule, bez cech sekretów i historii. Normalny run ustawia pustą instruction. |
| Cechy i pochodzenie | src/vault/types.rs; agents.rs; policy.rs:14–65 | Istnieją typ, rewizja, provider, deklaracje i źródła. DeclarationSources::default() przypisuje Owner, więc brak wiersza nie jest dowodem potwierdzenia przez właściciela. |
| Zmiany i użycia | src/vault/history.rs:21–29,55–59; usage.rs:103–139 | Są item_event i item_use. Stare zdarzenia nie zawierają pełnej historycznej rewizji ani aktora; zezwolenie nie dowodzi sukcesu u providera. |
| Decyzje i trening | src/vault/learning.rs:261–323; src/broker/finetune.rs:151–163,253–268,324–335 | Brak dokładnego snapshotu model input. Próg treningu liczy dziś wszystkie owner decisions; owner deny jest zwykle mapowane na task_match=no. |
| Budżet | tools/basemodel/serve.py:112–129; train.py:86,197 | Domyślnie 512 tokenów łącznie z pytaniem. Cache i collate mają 512 na sztywno. Nowego formatu nie wystarczy dopisać do tekstu. |
| Sync | src/vault/merge.rs:65–140 | item_event syncuje się; item_use i decision_log są lokalne. ID item_event nie jest lokalnym monotonicznym cutoffem. |
| Ocena kandydata | src/broker/shadow.rs; src/vault/candidate.rs | Są już głowy, shadow, promocja i rollback. Wykorzystujemy te mechanizmy. |

## 3. Kolejność prac

1. **A — kontrakt i macierz polityki.** Zamknięte cechy, granice upoważnienia, przypadki testowe.
2. **B — próba wykonalności modelu.** Format, tokenizer, głowa kontekstowa i mierzalny zbiór. Przed dużą migracją.
3. **C — lokalne snapshoty i shadow w aplikacji.** Bez zmiany wykonania. Zapis dokładnego wejścia.
4. **D — ocena oraz jawna decyzja o aktywacji.** Liczbowe kryteria, porównanie z dotychczasową ścieżką.
5. **E — uproszczenie procesu i usunięcie starego toru.** Dopiero po wynikach D; zachowane jawne upoważnienia.

A i B mają wykazać, że model potrafi wykorzystać cechy i historię. Jeżeli nie potrafi, nie dokładamy migracji ani warstw UI w nadziei, że później poprawią wynik.

## 4. Macierz polityki

W etapie shadow żadna obecna reguła wykonania nie zmienia znaczenia. Kandydat może ocenić kontekst po kontroli tożsamości i dostępu, także gdy obecny gate pyta przed inference; jego wynik jest tylko obserwacją. Dotyczy to również MissingDeclaration, inaczej znów uzyskalibyśmy zerowe pokrycie modelu.

Poniżej cały katalog ReasonKind z bazowego route_diagnostics.rs. Kolumna aktywacji opisuje pierwszy planowany zakres produkcyjny po D, a nie działanie dzisiejszej aplikacji.

| ReasonKind / przypadek | Pierwsza aktywacja po D |
| --- | --- |
| Other | Bez ogólnego automatycznego allow. Każda użyta ścieżka musi dostać sklasyfikowaną przyczynę. |
| AccessCheck | Lokalna odmowa: tożsamość, dostęp, revoke, archive/restore, pole/binding, expiry, limity, duplicate env names. |
| AlwaysAsk | Jawna preferencja właściciela pozostaje pytaniem niezależnie od modelu. |
| MissingTask | Pytanie. Historia sekretu nie zastępuje bieżącego zadania. |
| HookUnverified | Pytanie zgodnie z obecnym znaczeniem flagi; nie podnosimy agent-stated tekstu do zweryfikowanego zadania. |
| HookAmbiguous | Pytanie: nie wybieramy sesji ani zadania na podstawie historii. |
| HookFlags | Obecne flagi nadal pytają. Audyt i przeniesienie poszczególnych heurystyk do cech to osobna zmiana polityki; zakazy i ochrona ujawnienia zostają lokalne. |
| ForeignHost: host bazy danych | Zachowany lokalny veto; brain nie dopisuje hosta. |
| ForeignHost: pozostałe wykryte cele | Zachowana kontrola każdego celu dla każdego sekretu; tylko pasująca jawna odpowiedź właściciela rozszerza istniejący zakres. |
| ForeignProject | Zachowana kontrola i obecne znaczenie jawnej odpowiedzi właściciela. |
| NotProject | Zachowane obecne pytanie. Zmiana obsługi root/HOME wymaga osobnego przypadku w ADR. |
| Production: produkcyjne RW/admin | Zachowane pytanie z każdego źródła klasyfikacji, również przy poleceniu wyglądającym na odczyt. |
| Production: read-only i zdalny brain | Zachowane pytanie; zdalny brain poza pierwszym zakresem. |
| MissingDeclaration | Docelowo wejście declaration=none do nowej oceny. Usunięcie blokady jest nierozłączne z regułą ostrożności opisaną poniżej. |
| UnfitAnswer | Pytanie: model nie poszerza wcześniejszej zgody. |
| OneTimeCode | Bez zmiany: jawne upoważnienie na kod i dotychczasowe ograniczenia. |
| Connector | Bez zmiany, poza pierwszym zakresem process run. |
| BrowserFill | Bez zmiany; browser fill i passkeys zachowują własne upoważnienia. |
| CloudAgent | Bez zmiany: każda operacja pyta, osobne granice zaufania i weryfikacji zadania. |
| ModelUnavailable | Pytanie; brak cichego użycia starego wejścia lub niezgodnych głów. |
| ModelTimeout | Pytanie i obecne limity/retry. |
| LowTaskMatch | Nowa polityka bierze wersjonowany wynik modelu; brak wyjątków wprowadzanych bez ewaluacji. |
| ModelUnsure | Pytanie, z konkretnym brakiem pewności. |
| ModelAllowed | Wynik tylko dla zgodnego kontraktu, po kontrolach lokalnych i przed ponowną kontrolą wykonania. |
| RememberedAnswer | Zachowana jawna zgoda w dokładnym zakresie; checkbox Remember for this project pozostaje. Nie jest nową etykietą treningową. |
| RememberedPattern | Na czas shadow i pierwszego porównania zachowany. Zastąpienie dowodem w modelu dopiero po wykazaniu braku regresji na powtórzeniach. |

**Interakcja MissingDeclaration i produkcji:** bez deklaracji obecne facts.production może być fałszywe. Samo usunięcie MissingDeclaration omijałoby także obecną ochronę produkcyjną. Nowa ścieżka musi przed tym usunięciem odczytać zamknięty wynik lokalnego detektora. Strong production signal nadal wymaga pytania dla RW/admin. Environment lub scope nieznane wymagają pytania przy zmianie stanu albo gdy odczytu nie można wiarygodnie ustalić. Czysty, ustalony odczyt może wejść do nowej oceny po pozostałych kontrolach. Nieznane nie staje się dev ani potwierdzonym read-only.

Autonomia produkcyjnego zapisu, nowe hosty/projekty, cloud oraz przenoszenie flags do modelu są osobnymi, nazwanymi propozycjami późniejszego ADR. Nie są ukrytym efektem MissingDeclaration ani celu „mniej pytań”. Jawnych zakazów właściciela nie zastępujemy historią.

Ta macierz ma pokryć wszystkie odmiany powodów, a nie tylko nazwy enum. A wymaga testu sprawdzającego kompletność mapowania i przypadki produkcji/hostów w podtypach.

## 5. Minimalny kontrakt kontekstu

### 5.1 Jeden kontrakt zamiast czterech niezależnych wersji

Jeden context_contract identyfikuje i hashuje: schemat cech, serializer, kolejność/znaczenie pytań, politykę wyboru historii i tokenizer. Model manifest pinuje ten kontrakt, bazowy encoder i head hash. Poszczególne składowe pozostają w manifeście do diagnostyki; użytkownik nie przełącza ich osobno.

Nowy endpoint: POST /v1/context-evaluate, z deklarowaną obsługą context_contract w health. Stare /v1/systemone i bouncer-brain-v1/v2 zachowują znaczenie. Nieznany endpoint, nieobsługiwany kontrakt lub błędny head hash oznaczają niedostępność nowej oceny, bez cichego downgrade.

### 5.2 SecretFactsV1

Rust wylicza cechy z istniejących tabel i lokalnego detektora. Zamknięty słownik obejmuje wszystkie żądane sekrety:

- request-local referencję secret_1/secret_2/secret_3; rewizje i item UUID są wiązane lokalnie, nie w model text;
- typ/provider, environment i scope albo unknown, pochodzenie owner/signal/usage/default/legacy_unknown;
- zgodność projektu i celów jako kategorie, stan agent_created, czy to pierwsze użycie przez agenta;
- niedawną rotację i zmianę dostępu w przedziałach czasu;
- jawne owner approvals/denials dla porównywalnego zakresu: sekret, agent, projekt, akcja, rodzina komendy i cele;
- obecność konfliktu/sprzecznych sygnałów, history_coverage=local_device, brakujące dane i zakres czasowy.

Unknown pozostaje unknown. Brak declaration_source nie staje się Owner tylko dlatego, że tak działa stara funkcja default(); rzeczywiste zachowane potwierdzenie trzeba wykazać albo oznaczyć legacy_unknown. Jawne obecne ograniczenia pozostają egzekwowane nawet wtedy, gdy nie da się odtworzyć ich historycznego autora.

W pierwszej wersji nie podajemy modelowi wolnego tekstu notatek, nazw/custom pól ani dawnych poleceń. Nie jest to pełny docelowy model rekordu: jest to mały, sprawdzalny przekrój jego cech i historii. Bogatszy kontekst można dodać po dowodzie jego wartości i odporności. Surowe dane nadal są dostępne właścicielowi w szczegółach.

Automatyczne model allow i ich liczba nie są pozytywną cechą zaufania w pierwszej wersji. Binarne „był używany przez tego agenta” nie oznacza „był bezpiecznie używany”. Brak odpowiedzi nie jest odmową właściciela. Allow nie jest dowodem sukcesu operacji u providera.

### 5.3 Tekst bieżącego żądania i dwa rodzaje wejścia

Istniejące głowy faktów dostają obecny state_text, z tym samym maskowaniem. Nowa głowa kontekstowa dostaje bieżące zadanie/operację oraz SecretFactsV1. Nie zakładamy, że stare wagi rozumieją nowy tekst.

Kontekstowa głowa odpowiada na robocze pytanie owner_accepts_use: decyzja właściciela dla tej konkretnej sytuacji, a nie „obiektywne bezpieczeństwo”. Owner deny nie staje się automatycznie task_match=no; zgoda na niebezpieczną operację nie zmienia etykiety writes/destroy. W B porównujemy nową głowę z agregacją ocen faktów; jeśli osobna głowa nie działa, nie aktywujemy jej przez sam refaktor kodu.

Bieżący tekst agenta pozostaje nieufnym wejściem. Same etykiety provenance nie chronią przed manipulacją klasyfikatorem. Testy mierzą wpływ zmiany tekstu na decyzję i błędne zgody.

Dwa rodzaje wejścia mogą oznaczać osobne wiersze/passy encodera. B ma zmierzyć koszt; nie obiecujemy obecnego „jednego encoder pass” po rozszerzeniu kontraktu.

### 5.4 Budżet wylicza klient

Pierwsza implementacja kompaktuje lokalnie w Ruście. Tokenizer ma identyczny plik tokenizer.json, hash, opcje i format nagłówka jak serwer; wybór biblioteki Rust jest częścią B. Serwer i trener sprawdzają budżet, ale nie zmieniają odebranego model text.

Proponowany twardy limit pierwszego kontraktu: do 3 sekretów na ocenę; większy zbiór zachowuje zwykłe pytanie i jest liczony w ask rate. Limit jest jawny w kontrakcie. „20–40 tokenów na sekret” z krytyki jest hipotezą do pomiaru, nie przyjętym wynikiem.

Dane obowiązkowe i bieżące polecenie są kompletne. Cechy mają krótką, deterministyczną reprezentację; ograniczone okno 30 dni służy agregatom owner evidence i rotacji, nie wysyłaniu 20 tekstowych zdarzeń. Dawniejsze jawne ograniczenia nie wygasają po 30 dniach.

Gdy niezbędne dane nie mieszczą się w dokładnym budżecie danego pytania, context_unavailable oznacza pytanie. Wynik wlicza się do wszystkich wskaźników kosztu. Zwiększenie max_len wymaga osobnych pomiarów, zgodnego treningu i manifestu.

## 6. Jedna lokalna tabela snapshotów

Proponowane decision_context_snapshot zawiera decision_log_id/request ID, context_contract, dokładne oczyszczone model texts dla pytań, rewizje sekretów, model/head manifest, czas i lokalny observation_seq. Outcome i owner label są osobnymi zdarzeniami względem tego wejścia.

- observation_seq pochodzi z nowego lokalnego licznika w tej tabeli/transakcji; nie używamy item_event.id, czasu ściennego ani zsynchronizowanego sqlite_sequence jako cutoff.
- Cechy i widoczna historia są czytane spójnie z sejfu. Snapshot jest zapisem wiedzy dostępnej przed oceną; po etykiecie nie rekonstruujemy go z aktualnego stanu.
- Zapis snapshotu i powiązania decyzji jest atomowy albo jawnie incomplete po awarii. Niekompletny rekord nie jest przykładem treningowym.
- Nowa tabela trafia do LOCAL_TABLES i istniejącego mechanizmu strip lokalnych danych przed sync. Testuje się pushed copy, merge, backup i restore.
- Nie zmieniamy w tym etapie item_event, nie dodajemy rozproszonego event store ani synchronizacji użyć. Pokrycie local_device jest częścią wejścia.
- Snapshoty nigdy nie trafiają do skeleton contributions z ADR 0043. Wymagany negatywny test istniejącego eksportera.
- Retencja proponowana do pomiaru w C: maks. 10 000 zwykłych snapshotów i 2 000 owner-denial, łącznie maks. 64 MiB; pojedynczy rekord maks. 16 KiB. Limit bajtowy ma pierwszeństwo. Usuwamy najpierw starsze zwykłe, potem starsze denial; jawne ograniczenia pozostają w swoim magazynie.
- Po usunięciu snapshotu decyzja audytowa ma context_pruned; nie odtwarzamy brakującego wejścia i nie kwalifikujemy jej do nowego treningu.
- Zestawy treningowe korzystają z istniejących zasad przygotowania, manifestu i cleanup; nie dodajemy nowej osobnej retencji bez wskazania właściciela danych.
- Numer migracji wybiera implementer na aktualnym main. Baza 34 i rezerwacja ADR 0043 nie oznaczają wolnego numeru 35.

Po model allow sprawdzamy ponownie upoważnienie, binding i rewizje. Nowy jawny zakaz lub zmiana sekretu unieważnia ocenę; automatyczna telemetria nie robi tego sama. Zmiana samej historii nie może skutkować nieskończoną pętlą retry.

Po świeżym Allow właściciela nie uruchamiamy ponownie modelu dla tej samej operacji. Sprawdzamy aktualność dokładnie zatwierdzonego zakresu; jeśli jest nieaktualny, odpowiedź jest nieważna i potrzebna jest nowa decyzja, bez automatycznego rozszerzenia.

## 7. Trening i dane, których brakuje

Cold start oznacza głowy wyuczone na opisanych scenariuszach autora zbioru. To nie jest dowód nauczenia osobistych preferencji właściciela. Nowy użytkownik może korzystać z takiego modelu bazowego przed osobistym post-trainingiem, jeżeli przejdzie bramki B/D.

Próg osobistego treningu 300 owner decisions / 30 owner denials jest w pierwszym zakresie zachowany, ale oba liczniki muszą korzystać z tej samej kwalifikacji co generator przykładów: zgodny kompletny pre-decision snapshot, rzeczywista odpowiedź właściciela, obsługiwany kontrakt i zadanie. Legacy bez snapshotu nie otwiera bramki z pustym zbiorem.

Zmniejszenie liczby pytań utrudnia zebranie danych, szczególnie odmów. Dlatego:

- jawne Remember for this project pozostaje; nie zabieramy istniejącego sposobu ograniczania powtarzanych pytań, zanim model go zastąpi;
- Decisions dostaje opcjonalną ocenę dawnej automatycznej operacji „OK / Nie OK”, związaną z jej pierwotnym snapshotem. To etykieta oceny, nie zgoda na wykonanie ani zmiana dostępu;
- nie dokładamy losowych przerywających pytań kontrolnych domyślnie;
- raport osobno pokazuje etykiety z pierwotnych pytań i oceny auto-zgód; dobrowolne oceny nadal mają bias i nie są reprezentatywnym losowym zbiorem;
- bez danych o strefie auto-allow nie ogłaszamy, że osobisty model poprawia jej jakość;
- model allow, remembered answer, timeout i unanswered nie są nowymi owner labels.

Najpierw cięcie czasowe; następnie usunięcie z testu rodzin obecnych w train/validation. Deduplikujemy ponowienia tego samego logicznego żądania w oknie 10 minut, raportując osobno późniejsze jawne odwołanie decyzji. Wynik przedstawia pierwszą decyzję dla rodziny oraz powtórzenia, bez ukrywania zmian zdania właściciela.

Historia każdej próbki kończy się przed jej etykietą. Informacja o późniejszej odpowiedzi, komentarzu lub edycji nie trafia do wejścia. Odtwarzanie starej polityki nie dowodzi, jaką historię wygenerowałaby nowa; ta różnica jest jawna w raporcie shadow.

## 8. Jednostki, pliki i warunki ukończenia

| Jednostka | Własność i pliki | Warunki ukończenia |
| --- | --- | --- |
| A. Kontrakt i polityka | Nowy ADR z kolejnym wolnym numerem; docs/contracts/secret-decision-context-v1.md; tests/fixtures/secret-decision-context-v1/; tests/bouncer_brain_contract.rs | Pełna macierz ReasonKind i podtypów; rozróżnienie cech i ograniczeń; test braku deklaracji razem z produkcją; zamrożone definicje klas i metryki. |
| B. Próba modelu | Nowy src/broker/secret_facts.rs i testy wyliczania; src/broker/bouncer.rs; tools/basemodel/serve.py, train.py, common.py; tools/finetune/local_train.py; model manifest i fixtures Rust/Python | Lokalny tokenizer zgodny z Pythonem; zmierzony budżet i koszt dwóch wejść; syntetyczna głowa wykorzystuje cechy/historię; spełnione bramki offline. Można wykonać bez migracji prawdziwego sejfu. |
| C. Snapshot i lokalny shadow | Nowa migracja i src/vault/decision_context.rs; vault mod.rs/types.rs/merge.rs; broker run.rs/shadow.rs/finetune.rs; tests/vault_migration.rs i sync_schema_upgrade.rs | Dokładne wejście przy decyzji, wyłącznie lokalna tabela, usuwanie/retencja, prawdziwe legacy_unknown, eligibility count=dataset count, kandydat nie wpływa na wykonanie. |
| D. Ocena i pierwsza aktywacja | src/vault/candidate.rs; src/broker/shadow.rs, bouncer.rs, run.rs; docs/evaluation/; mała zmiana Decisions dla ocen auto-zgód | Wyniki per klasa i całość, spełnione liczby z §9; decyzja o semantyce MissingDeclaration zapisana w ADR; atomowe przełączenie zgodnego head+contract+policy. |
| E. Uproszczenie i usunięcia | broker run.rs/bouncer.rs/learning.rs/calibration.rs/patterns.rs/corrections.rs; desktop UI i CLI; docs/operations/bouncer.md, learning.md, fine-tune.md | Jedna docelowa ścieżka, brak MissingDeclaration jako formularza, brak osobnego pokrętła kalibracji, wzorce jako dowody po wykazaniu niegorszego wyniku powtórzeń. Diagnostyka pokazuje rzeczywisty etap i czas. |

A poprzedza B. B musi dowieść wykonalności przed C. C umożliwia D. E następuje po D. Jeden edytor odpowiada za wspólne run.rs/bouncer.rs/finetune.rs w danym czasie; nie dzielimy tych plików między równoległych implementerów.

## 9. Liczbowe bramki odbioru

To proponowane, wiążące progi planu przed treningiem. Nie są zaobserwowanymi wynikami.

### Offline przed integracją C

- Zamrożony test: co najmniej 300 normalnych i 300 ryzykownych niezależnie opracowanych scenariuszy, z rodzinami generatora nieobecnymi w train/validation. Osobny autor testu nie dostraja głów.
- Normalne: co najmniej 60% poprawnych auto-zgód ogółem i w każdej raportowanej klasie z co najmniej 50 przypadkami. Obowiązkowe klasy: cold start bez deklaracji, znany sekret z owner history, zmiana/rotacja, powtórzenia, wiele sekretów.
- Każda porównywalna klasa: odsetek pytań nie gorszy od starej polityki. Powtórzenia pokryte dotychczasowym pattern nie mogą stracić automatyzacji przy jego usunięciu; ten warunek sprawdzamy osobno w E.
- Jawnie niedozwolone: zero wykonań we wszystkich deterministycznych przypadkach, niezależnie od odpowiedzi modelu.
- Ryzykowne bez jawnego zakazu: zero fałszywych auto-zgód na co najmniej 300 przypadkach. Raport podaje N i nominalną jednostronną granicę 95%; dla 0/300 jest poniżej 1% przy założeniu niezależności. Zależne/syntetyczne przypadki nie uzasadniają takiej granicy dla ruchu produkcyjnego.
- Intended inference coverage: 100% mieszczących się, poprawnych kontekstów dla kandydata. Unavailable, timeout, przepełnienie i przekroczenie limitu sekretów liczą się jako pytania i są w mianowniku kosztu.
- Kanarki: zero tajnych wartości/fragmentów/kodowań w DTO, model input, snapshotach, eksporcie treningowym, HTTP, Debug i błędach. Pola tajne nie są serializowalne; wolny tekst z sekretu nie jest częścią v1.
- Parzystość: dokładnie to samo wejście i token budget w inference, replay i treningu; brak cichego obcięcia.
- Wydajność: klient mieści się w istniejących deadline'ach; p50/p95, CPU/MPS peak RAM i rozmiar snapshotu są raportowane przy 1 i 3 sekretach oraz maksymalnym wspieranym tekście. Brak liczbowego limitu RAM/latencji ustalonego z baseline w B blokuje B jako niedokończone.

Klasa normalna wynika z niezależnego oczekiwanego wyniku, nie z tego, co model dopuścił. Raport podaje oddzielnie koszty twardych bramek; nie ukrywa ich przez usunięcie z mianownika ogólnego ask rate.

### Lokalny shadow przed aktywacją D

Proponowane minimum: 14 dni oraz 100 rzeczywistych odpowiedzi właściciela ze zgodnym snapshotem, w tym 30 różnych rodzin operacji. Sam upływ czasu nie wystarcza. Dodatkowo oceniamy co najmniej 30 wcześniejszych auto-zgód wybranych niezależnie od wyniku kandydata przez listę review; właściciel może odmówić tej oceny, wtedy dowód pozostaje niekompletny.

Kandydat musi zachować jawne ograniczenia i nie zezwolić na żadną obserwowaną odmowę właściciela; wynik zgód/pytania prezentujemy z mianownikami i przedziałami, oddzielnie dla wyboru review i pytań pierwotnych. Minimum powyżej nie daje statystycznej gwarancji błędu poniżej 1% w rzeczywistym ruchu; nie łączymy go z syntetycznym N, żeby taką gwarancję sugerować.

Shadow jest proponowanym późniejszym etapem produktu, a nie upoważnieniem do odczytania danych właściciela w obecnym zadaniu planistycznym. Realny eksperyment wymaga jawnego włączenia i wskazania, jakie lokalne dane zapisuje.

### Kontrole techniczne i evidence tiers

Testy: revoke/rotacja w trakcie modelu i odpowiedzi, owner Allow bez ponownego modelu, wielu agentów, wiele sekretów, obcy host/projekt, brak zadania, injection w bieżącym tekście, spam zdarzeń, brak kontekstu, stary head/server, lock, restart, crash między snapshotem a decyzją, restore i sync strip.

Pełne Rust/nextest i doc tests uruchamia CI na dokładnym commicie; green draft nie zastępuje ready-PR z testami macOS. Lokalnie tylko skupione sprawdzenia przez ~/.local/bin/heavy-check i osobny target z cleanup. Modele mierzymy na danych sztucznych w izolowanym środowisku. Bez lokalnego Docker VM, produkcyjnego VPS i nowych płatnych usług.

Native QA obejmuje pytanie, Allow, Dismiss, pamiętanie zakresu, ocenę dawnej auto-zgody, timeout i lock. Testy fixture/CI nie dowodzą działania realnego providera, urządzenia ani publikacji.

## 10. Migracja, powrót i zakres odłożony

Nowy schemat dodajemy dopiero w C, po dowodzie B. Przez co najmniej jedno skoordynowane wydanie po pierwszej aktywacji zachowujemy kompatybilny stary tor w nowym binarium jako kontrolowany rollback. Jego wybór nie może poszerzać jawnych ograniczeń ani ignorować nowego revoke. E wskazuje konkretny następny release usuwający tor i warunki; nie robimy stałego przełącznika dwóch architektur dla użytkownika.

Nie cofamy schematu ani nie przywracamy backupu automatycznie — utraciłoby to późniejsze sekrety i decyzje. Starsza aplikacja nie obchodzi wersji schematu. Powrót dotyczy zgodnego head+policy w binarium obsługującym nową bazę.

Odłożone: wolny tekst z historii/notatek, pełny event store, sync użyć między urządzeniami, zmiana autonomii produkcyjnej, cloud, browser/OTP/passkey/connector, zdalny kontekst i masowa przebudowa UI. Docelowy bogatszy model sekretu wymaga osobnych dowodów, nie jest uznany za ukończony przez ograniczone SecretFactsV1.

Zdalne inference/training wymaga rozszerzonego kontraktu i aktualizacji zgody hostingowej przed przekazaniem nowych cech/historii. Stara zgoda nie poszerza się automatycznie. Snapshoty pozostają poza shared contributions.

Publikacja następuje na jednej nowej wersji wszystkich sześciu komponentów, z weryfikacją każdego kanału według AGENTS.md. Ten plan nie wybiera numeru release i nie zleca publikacji.

## 11. Odpowiedź autora na krytykę

| Ustalenie Opusa | Zmiana w wersji 2 |
| --- | --- |
| P0-1 niejawne zmiany uprawnień | Pełna macierz §4; hosty, projekt, flags, zadanie i zdalna produkcja zachowane w pierwszej aktywacji. |
| P0-2 MissingDeclaration omija produkcję | Jawna reguła interakcji w §4 oraz test, zanim blokada zostanie usunięta. |
| P1-3 budżet i kompaktowanie | §5: małe cechy, do 3 sekretów, klient Rust z przypiętym tokenizerem, osobny format nowej głowy. Brak tekstowej listy 20 zdarzeń. |
| P1-4 własne zgody jako zaufanie | §5/7: nie są pozytywną cechą; dodana ocena auto-zgód i jawne ograniczenie selective labels. |
| P1-5 zatrucie historii | Wolny tekst sekretu/historii poza v1; zamknięte cechy, agent_created i testy wpływu na decyzję. |
| P1-6 300/30 i cofnięcie pamiętania | Liczniki kwalifikowanych snapshotów; zachowane Remember i tymczasowy pattern do dowodu braku regresji. |
| P1-7 zawsze-pytający model | Konkretne progi, liczebności, wszystkie unavailable w ask rate, osobna bramka realnego shadow. |
| P2-8 temporal leakage i ponowienia | §7: kolejność podziału, rodziny, deduplikacja i ograniczenie off-policy. |
| P2-9 sync/legacy/rollback | Nowy lokalny cutoff, test strip, legacy_unknown, jawny brak contributions i rollback bez cofania danych. |
| P2-10 złożoność | Jeden context_contract, jedna nowa tabela, model spike przed migracją, mniejszy zakres. Owner Allow nie wraca do modelu. |

Nie przyjęto jako faktu: szacunkowej liczby tokenów na zdarzenie ani gwarancji, że 20–40 tokenów cech wystarczy. Nie przyjęto losowych pytań kontrolnych jako domyślnego UX. Cechy same z siebie nie dowodzą odporności modelu; wymagają pomiaru B/D.

To odpowiedź autora na jedną recenzję, nie ponowna aprobata Opusa. Wdrożenie pozostaje niewykonane.
