# apassy — koncepcja produktu

Status: projekt funkcji, nie gotowa implementacja. Aktualizacja: 2026-09-16.

## Cel

Agent może wykonać dozwoloną operację, ale nie otrzymuje wartości sekretu. Apassy udostępnia kontrolowane działania zamiast ogólnego `get_secret`.

Gwarancja wymaga izolacji brokera od procesu agenta. Agent z dowolnym dostępem do plików, pamięci lub konta brokera może ominąć tę granicę. Ukrycie sekretu przed modelem nie zapobiega samo w sobie nadużyciu dozwolonego API.

## Podstawowe funkcje

- Lokalny broker z CLI i MCP oraz niewielkim katalogiem jawnie dozwolonych operacji.
- Integracje z istniejącymi magazynami sekretów zamiast obowiązkowej migracji do nowego sejfu.
- Schemat konfiguracji dostępny dla agenta: nazwy pól, typy, wymagania i dostępność, bez wartości sekretów.
- Polityki per agent, sesja, projekt, środowisko, zasób i operacja; domyślna odmowa.
- Krótkotrwałe uprawnienia, limity użyć i natychmiastowe unieważnianie kolejnych operacji.
- Delegowanie subagentom wyłącznie podzbioru uprawnień rodzica, bez wydłużania ich ważności.
- Zgoda człowieka związana z konkretną operacją, nie ogólne udostępnienie klucza.
- Tryb próbny: podgląd decyzji polityki i planowanego działania bez pobrania sekretu.
- Audyt decyzji i wykonania bez wartości sekretów.
- Przekazywanie sekretów przez env jako osobny tryb kompatybilności o słabszych gwarancjach. Proces otrzymujący env może odczytać sekret.

## Bouncer: warstwa oceny ryzyka z Jev

Inspiracja: [TypeSafe — Introducing System One Models & Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev).

TypeSafe opisuje System One jako modele podejmujące szybkie, typowane decyzje na podstawie stanu programu. Jev ma zwracać oceny probabilistyczne i informacje o pewności zamiast swobodnego tekstu. Artykuł przedstawia produkt w early access. Deklaracje o kalibracji, wydajności i braku błędów typów pochodzą od dostawcy; nie są niezależnym dowodem bezpieczeństwa dla apassy.

Poprawny typ wyniku nie gwarantuje poprawnej klasyfikacji ryzyka. Proponowane poniżej metryki są kontraktem apassy, a nie potwierdzonymi polami API Jev. Integracja wymaga sprawdzenia dokumentacji, dostępu do usługi i warunków przetwarzania danych.

### Miejsce w przepływie

1. Broker uwierzytelnia agenta i odczytuje zaufany kontekst sesji oraz zadania.
2. Normalizuje operację i sprawdza twarde reguły: zakres uprawnień, zasób, środowisko, metodę, parametry, TTL i limity.
3. Naruszenie reguły kończy się odmową przed wywołaniem modelu i pobraniem sekretu.
4. Bouncer przekazuje do Jev minimalny, zredagowany opis operacji i kontekstu.
5. Jev klasyfikuje kilka wymiarów ryzyka. Deterministyczny kod apassy waliduje wynik i wyznacza `deny`, `require_approval` albo `allow`.
6. Jeśli jest wymagana zgoda człowieka, broker czeka na zatwierdzenie dokładnie tej operacji.
7. Bezpośrednio przed wykonaniem broker ponownie sprawdza ważność uprawnienia, zgodę, limity i unieważnienie. Dopiero wtedy pobiera sekret i wykonuje operację.
8. Broker kontroluje odpowiedź i zapisuje zdarzenie audytowe bez sekretu.

`allow` z bouncera nigdy nie nadaje nowych uprawnień ani nie uchyla twardej odmowy. Zgoda człowieka również nie omija polityki; jej zmiana jest osobną operacją administracyjną. Zmiana parametrów żądania unieważnia wcześniejszą ocenę i zgodę.

### Proponowane wymiary klasyfikacji

| Wymiar | Pytanie | Źródło sygnału |
| --- | --- | --- |
| Zgodność z zadaniem | Czy operacja odpowiada zatwierdzonemu celowi użytkownika? | Zaufany opis zadania i znormalizowana operacja |
| Ryzyko prompt injection | Czy niezaufane treści próbują zmienić cel lub zasady dostępu? | Oznaczone fragmenty treści narzędzi i ich pochodzenie |
| Ryzyko eksfiltracji | Czy operacja może ujawnić sekret lub chronione dane? | Cel połączenia, schemat parametrów, oczekiwany wynik |
| Eskalacja uprawnień | Czy operacja wykracza poza potrzebę zadania lub próbuje uzyskać szerszy dostęp? | Zakres operacji, delegowanie i historia sesji |
| Wrażliwość i skutki | Czy operacja dotyczy produkcji, danych wrażliwych albo nieodwracalnej zmiany? | Zaufana klasyfikacja zasobu i katalog operacji |
| Anomalia zachowania | Czy sekwencja lub częstotliwość działań odbiega od oczekiwanego przepływu? | Liczniki i ograniczona historia utrzymywana przez broker |

Dla każdego wymiaru kontrakt powinien zawierać klasę, rozkład prawdopodobieństwa i informację o niepewności, w zakresie faktycznie obsługiwanym przez API. Prawdopodobieństwo ryzyka nie jest tym samym co pewność klasyfikacji. Brak danych nie oznacza niskiego ryzyka.

Nie traktujemy deklaracji agenta typu „użytkownik zatwierdził” jako dowodu. Pochodzenie danych i uprawnienia ustala broker. Tekst pochodzący z narzędzi pozostaje niezaufany również dla bouncera.

### Reguły decyzji

- Twarda odmowa polityki: `deny`, niezależnie od modelu.
- Krytyczny sygnał ryzyka powyżej progu zweryfikowanego w testach: `deny`.
- Niepewność, niepełny kontekst lub podwyższone ryzyko: `require_approval` albo `deny`, zgodnie z polityką zasobu.
- Dopuszczalna operacja, kompletna ocena i niskie ryzyko we wszystkich wymaganych wymiarach: kandydat do `allow`.
- Timeout, niedostępność dostawcy, nieprawidłowy wynik lub nieznana wersja kontraktu: brak automatycznego dopuszczenia. Wymagana zgoda albo odmowa.

Nie używamy jednej średniej ważonej jako jedynej bramki: niskie ryzyko w jednym wymiarze nie może zamaskować krytycznej eksfiltracji w innym. Progi są wersjonowane per typ operacji i środowisko. Nie ustalamy produkcyjnych wartości bez danych ewaluacyjnych.

### Ochrona danych i egzekwowanie decyzji

- Do Jev nie trafiają wartości sekretów, nagłówki uwierzytelniające ani pełne env.
- Kontekst jest budowany z dozwolonych pól. Parametry, adresy URL, wyniki narzędzi i fragmenty rozmowy również mogą zawierać sekrety; nie wysyłamy ich automatycznie w całości.
- Zewnętrzne przetwarzanie wymaga jawnej konfiguracji oraz oceny retencji, regionu i warunków dostawcy. Redakcja nie gwarantuje anonimowości.
- Broker działa poza sandboxem agenta. Agent nie ma dostępu do jego magazynu ani poświadczeń dostawcy modelu.
- Każde dopuszczenie wiążemy z agentem, sesją, identyfikatorem uprawnienia, wersją polityki i skrótem kanonicznej operacji. Zgody mają TTL i limit użyć.
- Limity użyć egzekwujemy atomowo. Powtórzenie żądania nie może ponownie wykorzystać jednorazowej zgody.
- Broker kontroluje host, port, metodę, ścieżkę, parametry i przekierowania. Chroni przed SSRF, zmianą hosta i DNS rebindingiem niezależnie od oceny Jev.
- Preferujemy typowane operacje i ograniczone odpowiedzi zamiast dowolnego proxy HTTP. Filtrowanie odpowiedzi jest dodatkowym zabezpieczeniem, nie dowodem braku wycieku.
- Unieważnienie blokuje przyszłe wykonania; nie cofa już wykonanych zmian ani wcześniej ujawnionych danych.

### Audyt

Zapis obejmuje identyfikator żądania, tożsamość agenta, referencję sekretu, typ operacji, decyzję twardej polityki, oceny ryzyka, decyzję bouncera, zgodę człowieka, wersję modelu i konfiguracji, opóźnienie oraz wynik wykonania.

Nie zapisujemy surowych promptów, wartości sekretów ani dowolnych odpowiedzi API. Również metadane audytowe wymagają kontroli dostępu i retencji. Kody powodów mają pochodzić ze zdefiniowanego katalogu, nie ze swobodnego wyjaśnienia modelu.

### Weryfikacja przed wdrożeniem

- Zestaw przypadków z etykietami: poprawne działania, prompt injection, eksfiltracja, eskalacja i niejednoznaczny kontekst.
- Pomiar fałszywych dopuszczeń, fałszywych blokad i odsetka eskalacji do człowieka; osobno dla typów operacji i środowisk.
- Sprawdzenie kalibracji ocen na własnych danych, nie tylko benchmarkach dostawcy.
- Testy odporności na parafrazy, kodowanie treści, długi kontekst i próby manipulacji bouncerem.
- Testy deterministycznej polityki, timeoutów, nieprawidłowych wyników, replay, zmian żądania i unieważnienia podczas oczekiwania.
- Pomiar opóźnień p50/p95/p99 oraz kosztu na operację.
- Tryb obserwacyjny najpierw w sandboxie: Jev ocenia, ale nie zmienia wyniku bazowej polityki. Następnie ograniczone egzekwowanie i stopniowe rozszerzanie po ocenie błędów.

## Zakres pierwszej wersji

1. Broker CLI + MCP, tożsamości sesji i kilka typowanych operacji.
2. Jeden adapter magazynu sekretów i deterministyczna polityka z domyślną odmową.
3. Zgody człowieka, TTL, limity, unieważnianie i audyt.
4. Interfejs `RiskEvaluator`, adapter Jev oraz deterministyczny adapter testowy. Adapter testowy nie zastępuje oceny ryzyka w produkcji.
5. Bouncer w trybie obserwacyjnym, potem egzekwowanie progów zweryfikowanych w testach.

Bez dostępu do Jev można zbudować i testować kontrakt oraz politykę. Nie można wtedy potwierdzić działania integracji, jakości klasyfikacji ani rzeczywistych opóźnień.
