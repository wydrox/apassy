# apassy — Product Vision v1

Data: 2026-09-16.

Status: wizja produktu i plan zakresu przed implementacją. „v1” w tytule oznacza wersję dokumentu; MVP i wersja produktu v1 są osobnymi etapami opisanymi poniżej. Dokument nie potwierdza wdrożenia funkcji ani gotowości produkcyjnej.

Szczegóły architektury bouncera: [koncepcja produktu](concept.md).

## Wizja

Agent może wykonać dozwoloną operację, ale nie otrzymuje wartości sekretu. Apassy kontroluje użycie uprawnień, zamiast udostępniać agentowi ogólny odczyt sekretów.

MVP jest przeznaczone dla pojedynczego użytkownika i lokalnych agentów. Wersja produktu v1 rozszerza ten model na zespoły, subagentów i CI.

Ukrycie sekretu przed modelem nie zapobiega samo w sobie nadużyciu dozwolonego API. Ochrona wymaga izolacji brokera, twardych polityk i kontroli wykonywanych operacji. Ocena modelu jest dodatkową warstwą, nie zamiennikiem tych mechanizmów.

## MVP — jeden kompletny, bezpieczny przepływ

### Cel

Agent wykonuje rzeczywiste zadanie przez apassy. Użytkownik kontroluje uprawnienia i widzi powód decyzji.

### Zakres

1. **Lokalny broker, CLI i MCP.** Osobny interfejs administracyjny dla człowieka. Agent nie może zatwierdzać własnych żądań.
2. **Jeden wspierany sposób izolacji.** Broker działa poza sandboxem agenta. Agent nie ma dostępu do magazynu, konfiguracji ani poświadczeń brokera. Izolacja jest częścią MVP, nie późniejszym ulepszeniem.
3. **Jeden adapter magazynu.** Proponowany start: lokalny, szyfrowany magazyn oparty na sprawdzonym narzędziu, bez własnej kryptografii. Interfejs jest przygotowany pod zewnętrznych dostawców.
4. **Jedna integracja operacyjna.** Proponowany start: GitHub — odczyt statusu workflow, odczyt statusu PR i uruchomienie wskazanego workflow z ograniczonymi parametrami. Bez dowolnych adresów URL i ogólnego proxy.
5. **Schemat widoczny dla agenta.** Dostępne operacje, wymagane pola i dostępność poświadczeń, bez odczytu ich wartości.
6. **Twarde polityki.** Agent, sesja, repozytorium, operacja, parametry, TTL i limit użyć. Domyślna odmowa.
7. **Kontrola człowieka.** Zgoda na konkretną operację, jednorazowe zatwierdzenie, unieważnianie dostępu i tryb próbny bez wykonania.
8. **Bouncer Jev.** Ocena ryzyka w granicach twardych polityk, zgodnie z opisem poniżej.
9. **Lokalny audyt.** Tożsamość agenta, operacja, decyzja polityki, oceny bouncera, zgoda i wynik. Bez sekretów i surowych rozmów.

### Bouncer Jev w MVP

Warstwa inspirowana [TypeSafe System One i Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev) ocenia sześć wymiarów:

- zgodność operacji z zadaniem;
- ryzyko prompt injection;
- ryzyko eksfiltracji;
- eskalację uprawnień;
- wrażliwość zasobu i skutki operacji;
- anomalie zachowania.

Jev dostarcza klasyfikacje. Deterministyczny kod apassy wyznacza wynik: blokada, wymagana zgoda człowieka albo dopuszczenie.

Wdrażanie odbywa się etapami:

1. Tryb obserwacyjny w sandboxie, bez zmiany wyniku bazowej polityki.
2. Blokowanie lub wymaganie zgody na podstawie zweryfikowanych ocen.
3. Automatyczne dopuszczenie wyłącznie dla wąskiego, przetestowanego zestawu operacji.

Awaria, nieprawidłowy wynik lub niepewność nigdy nie oznaczają automatycznej zgody. Model i zgoda człowieka nie mogą uchylić twardej odmowy. Wartości sekretów nie trafiają do Jev. Kontekst przekazywany dostawcy jest minimalizowany i podlega jawnej konfiguracji.

Proponowane metryki są kontraktem apassy, nie potwierdzonymi polami API Jev. Poprawny typ wyniku nie gwarantuje poprawnej klasyfikacji. Dostęp do usługi, API i warunki przetwarzania wymagają weryfikacji przed integracją.

### Poza MVP

- Panel webowy, organizacje, SSO i billing.
- Rozszerzenie przeglądarkowe i menedżer haseł dla ludzi.
- Dowolny HTTP proxy, dowolne polecenia shell i przekazywanie sekretów do env agenta.
- Kubernetes, wiele backendów, automatyczna rotacja i delegowanie subagentom.
- Deklaracja gotowości do operacji wysokiego ryzyka na produkcji.

### Kryteria gotowości MVP

1. Pełny scenariusz GitHub działa od żądania agenta do kontrolowanego wyniku.
2. Testy potwierdzają blokowanie obejścia polityki, zmiany zatwierdzonego żądania, ponownego użycia zgody i przekroczenia limitów.
3. Testowe sekrety nie pojawiają się w kontekście modelu, odpowiedziach MCP ani logach w sprawdzanych scenariuszach. Wynik testów nie jest uniwersalną gwarancją braku wycieku.
4. Awaria Jev i unieważnienie sesji mają sprawdzone zachowanie.
5. Dostępny jest raport błędnych dopuszczeń, blokad, eskalacji, opóźnień i kosztów — nie tylko działające demo.

Dostęp do Jev jest zależnością. Bez niego można zbudować rdzeń i testy, ale nie uznać integracji bouncera za ukończoną.

## Wersja produktu v1 — regularna praca zespołu

### Cel

Wiele agentów i środowisk korzysta z powtarzalnego zarządzania dostępem, opartego na sprawdzonym przepływie MVP.

### Zakres ponad MVP

1. **Projekty, środowiska i role.** Właściciel, administrator polityk, zatwierdzający i operator agenta.
2. **Panel webowy.** Konfiguracja, kolejka zgód, historia decyzji i natychmiastowe odwołanie sesji.
3. **Delegowanie subagentom.** Wyłącznie podzbiór uprawnień rodzica, krótsza ważność i śledzenie całego łańcucha.
4. **OIDC dla CI i workloadów.** Krótkotrwałe tożsamości zamiast stałych tokenów do apassy.
5. **Dwa zewnętrzne backendy.** Proponowane: OpenBao i Infisical. Dynamiczne poświadczenia tam, gdzie dostawca je zapewnia.
6. **Kolejne typowane integracje.** Wybór na podstawie pilotażu. Wersjonowane kontrakty i SDK do tworzenia adapterów.
7. **Dojrzały bouncer.** Wersjonowanie progów, porównywanie modeli, ponowne odtwarzanie ocen na zapisanych bezpiecznych przypadkach, wykrywanie pogorszenia jakości i kontrolowane wdrażanie zmian.
8. **Polityki jako kod.** Walidacja, podgląd różnic i testy przed aktywacją.
9. **Eksploatacja i audyt.** Audyt odporniejszy na manipulację, eksport, retencja, kopie zapasowe i procedura odtwarzania.
10. **Ograniczony tryb env.** Sekrety dla wskazanych procesów, wyraźnie oddzielone od gwarancji „agent nie otrzymuje sekretu”. Proces otrzymujący env może odczytać jego wartości.

### Kryteria gotowości v1

- Pilotaż zespołowy obejmuje lokalnych agentów, subagentów i CI.
- Sprawdzona jest izolacja projektów, odzyskiwanie po awarii i aktualizacje.
- Przeprowadzono niezależny przegląd bezpieczeństwa i zamknięto krytyczne ustalenia.
- Udokumentowano granice ochrony, wspierane konfiguracje i zmierzone parametry działania.

## Kolejność realizacji

1. Izolacja i model zagrożeń.
2. Broker i twarde polityki.
3. Jedna integracja operacyjna.
4. Zgody i audyt.
5. Jev i ewaluacja bouncera.
6. Pilotaż MVP.
7. Rozszerzenia do wersji produktu v1.

## Zasada ograniczania zakresu

MVP ma udowodnić jedną bezpieczną ścieżkę od początku do końca, a nie obsługiwać wszystkie sekrety i narzędzia. Konkretne narzędzie szyfrujące, sposób izolacji i stos technologiczny pozostają decyzjami implementacyjnymi. Proponowane integracje są kierunkiem planu, a nie już istniejącymi funkcjami.
