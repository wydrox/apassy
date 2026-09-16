# apassy — Product Infra v1

Data: 2026-09-16.

Status: otwarty plan infrastruktury i architektury przed implementacją. „v1” oznacza wersję dokumentu, nie gotowość produktu. Plan określa wymagania i kryteria decyzji, ale nie wybiera języka, bibliotek, bazy danych, chmury ani sposobu wdrożenia.

Dokument uzupełnia [Product Vision v1](product-vision-v1.md) i [koncepcję produktu](concept.md). Nie rozszerza zakresu MVP. Wymagania bezpieczeństwa są granicami projektu; przykłady technologii są opcjami do oceny.

## 1. Cele

- **Lekkość:** mało procesów, zależności i obowiązkowych usług; ograniczone zużycie pamięci, CPU oraz dysku.
- **Bezpieczeństwo:** agent wykonuje dozwoloną operację bez otrzymania wartości sekretu, w jasno określonej granicy izolacji.
- **Łatwe aktualizacje:** weryfikowalne wydania, kontrolowane migracje i sprawdzona procedura odzyskania działania.
- **Rozbudowywalność:** nowe integracje bez przebudowy rdzenia autoryzacji i bez automatycznego rozszerzania uprawnień.
- **Szybkość:** niski, mierzalny narzut lokalny; czas usług zewnętrznych raportowany oddzielnie.
- **Prostota utrzymania:** mały zestaw komponentów, czytelne kontrakty i możliwość diagnozy bez ujawniania sekretów.

Nie optymalizujemy rozmiaru ani opóźnień kosztem izolacji, trwałości zgód lub poprawności polityki. Sam wybór języka nie zapewnia tych właściwości.

## 2. Kierunek architektury

Preferowany punkt wyjścia to niewielki, modułowy rdzeń zamiast mikroserwisów. Granice logiczne nie muszą oznaczać osobnych usług, ale granica między agentem a brokerem musi być rzeczywistą granicą uprawnień.

Odpowiedzialności:

- interfejsy CLI i MCP;
- tożsamości, sesje i deterministyczna polityka;
- ocena ryzyka przez bouncera;
- zgody człowieka i limity użyć;
- pobieranie sekretów i wykonywanie typowanych operacji;
- trwały stan, audyt i diagnostyka.

Przepływ: uwierzytelnienie → twarda polityka → ocena ryzyka → ewentualna zgoda → ponowna kontrola uprawnień → użycie sekretu przez broker → kontrolowany wynik i audyt.

Dystrybucja powinna wymagać możliwie niewielu kroków. Jeden plik wykonywalny jest atrakcyjną opcją, nie wymogiem. MVP nie powinno wymagać klastra, zewnętrznej kolejki ani wielu serwerów tylko do lokalnego działania. Lokalny rdzeń nie oznacza pracy całkowicie offline: Jev i docelowe API mogą wymagać sieci.

## 3. Wybór technologii pozostaje otwarty

Rust i Go są głównymi kandydatami dla rdzenia. Inny stos jest dopuszczalny, jeśli spełnia wymagania i ma uzasadnienie. Żaden język nie został wybrany.

Porównanie powinno uwzględnić:

- bezpieczeństwo pamięci oraz zakres kodu natywnego, FFI i operacji niebezpiecznych;
- dojrzałość bibliotek kryptograficznych, sieciowych i protokołów;
- możliwość ograniczania kopii i czasu życia sekretów;
- rzeczywiste zużycie zasobów, rozmiar dystrybucji i czas startu;
- łatwość budowania, aktualizacji i obsługi docelowych systemów;
- liczbę, jakość, licencje i utrzymanie zależności;
- doświadczenie zespołu, koszt przeglądu kodu i tempo rozwoju.

Bezpieczeństwo pamięci nie oznacza braku wycieku sekretów, błędów autoryzacji ani odmowy usługi. Rust nie usuwa ryzyka błędnego `unsafe` lub FFI; język z GC nie gwarantuje szybkiego usunięcia kopii danych. Żaden wariant nie powinien obiecywać całkowitego wymazania sekretu z pamięci bez udowodnienia konkretnego zakresu tej gwarancji.

Istotne decyzje zapisujemy krótko: problem, rozważone warianty, dowody, wybór, kompromisy i warunki ponownej oceny. Nie projektujemy wymienności każdego elementu na zapas.

## 4. Granice bezpieczeństwa

- Broker działa poza sandboxem agenta. Sam osobny proces lub port na localhost nie stanowi wystarczającej izolacji.
- Agent nie ma dostępu do kluczy, magazynu, konfiguracji polityk ani poświadczeń Jev. Kanał administracyjny nie jest dostępny dla agenta.
- Każda operacja wymaga uwierzytelnienia i autoryzacji. Brak reguły oznacza odmowę.
- Zgoda jest związana z tożsamością, sesją, konkretną operacją, parametrami, wersją polityki i terminem ważności. Limity użyć są egzekwowane atomowo.
- Przed wykonaniem ponownie sprawdzamy unieważnienie i ważność zgody. Zmiana operacji wymaga nowej oceny.
- Kontrola celu połączenia, przekierowań i dostępu do sieci nie zależy od modelu. Projekt uwzględnia SSRF i DNS rebinding.
- Interfejsy agenta nie udostępniają ogólnego odczytu sekretów, wykonywania dowolnego shell ani dowolnego proxy.
- Sekret nie trafia do zwykłych logów, błędów, śladów diagnostycznych ani kontekstu modelu. Ograniczamy też dane zwracane przez usługę docelową.
- Model zagrożeń jawnie opisuje ryzyka poza zakresem ochrony, np. przejęcie systemu lub konta administracyjnego brokera.

Dla MVP wybieramy jeden sprawdzony model izolacji i jasno podajemy wspierane systemy. Nie deklarujemy równoważnych gwarancji na platformach, których nie przetestowano.

## 5. Dane i kryptografia

Oddzielamy logicznie metadane, sesje, zgody i audyt od wartości sekretów oraz materiału kluczowego.

Lokalny magazyn transakcyjny, np. SQLite, jest opcją dla MVP, nie decyzją. Rozwiązanie musi zapewniać atomowość zużycia zgód, spójność limitów, odzyskanie po awarii i wersjonowanie schematu. Nie przechowujemy sekretów jawnym tekstem w bazie metadanych.

Szyfrowanie korzysta ze sprawdzonych bibliotek i formatów. Nie tworzymy własnego algorytmu ani protokołu kryptograficznego. Wybór magazynu i kluczy uwzględnia uruchomienie brokera, odblokowanie, kopie zapasowe, utratę klucza i późniejszą rotację. Systemowy keychain nie zastępuje izolacji od agenta o tych samych uprawnieniach.

Audyt ma kontrolę dostępu, retencję i ograniczenie rozmiaru. W v1 rozwijamy odporność na manipulację i eksport. Brak miejsca na dysku lub niemożność zapisania wymaganego audytu muszą mieć jawne, przetestowane zachowanie; nie mogą prowadzić do cichego wykonania poza polityką.

## 6. Jev i zależności zewnętrzne

Bouncer jest adapterem oceny ryzyka, nie źródłem uprawnień. Jego wymiana nie może zmieniać twardych zasad dostępu.

- Wysyłamy tylko dozwolony, minimalny kontekst, nigdy wartości sekretów.
- Walidujemy wynik i obsługujemy brak danych, niepewność, timeout oraz niedostępność usługi.
- Awaria nie daje automatycznej zgody. Możliwa jest odmowa albo zgoda człowieka, zgodnie z polityką.
- Ograniczamy czas, koszt, współbieżność i liczbę ponowień.
- Nie ponawiamy bezwarunkowo operacji zmieniających stan; potrzebna jest strategia idempotencji i obsługi nieznanego wyniku.
- Cache nie może pomijać unieważnienia, zmiany polityki, TTL ani limitu użyć.
- Dostęp do API, warunki przetwarzania, retencja i region są sprawdzane przed integracją.

Testowy adapter pozwala rozwijać rdzeń bez usługi zewnętrznej, ale nie stanowi dowodu jakości klasyfikacji Jev. Tę jakość sprawdzamy osobną ewaluacją na danych właściwych dla apassy.

## 7. Rozbudowywalność

Definiujemy niewielkie kontrakty dla magazynu sekretów, oceny ryzyka i typowanych operacji. Kontrakty opisują uprawnienia, format wejścia i wyjścia, błędy, wersję oraz skutki uboczne.

W MVP preferujemy kontrolowany zestaw adapterów dostarczanych z aplikacją. Nie zakładamy otwartego systemu wtyczek uruchamianych z pełnymi uprawnieniami brokera. Zewnętrzny adapter w przyszłości wymaga osobnej oceny zaufania i ograniczenia możliwości, np. przez izolowany proces. Konkretnego mechanizmu nie wybieramy teraz.

CLI, MCP i przyszły panel używają tych samych reguł autoryzacji. Panel v1 nie powinien wymagać ciężkiego środowiska uruchomieniowego bez wyraźnej potrzeby; sposób jego budowania pozostaje otwarty.

## 8. Dystrybucja i aktualizacje

- Wydania mają weryfikowalne pochodzenie i integralność, np. podpisy oraz poświadczenia procesu budowania. Sama suma kontrolna nie potwierdza wydawcy.
- Narzędzia budowania i zależności są wersjonowane. CI sprawdza podatności, licencje i skład wydania.
- Aktualizacje uruchamia administrator, nie agent. Mechanizm dostarczenia może korzystać z menedżera pakietów lub innego kontrolowanego kanału.
- Aktualizacja nie powinna pozostawiać częściowo wymienionej instalacji. Niekompatybilne wersje protokołu lub danych mają jawne zachowanie.
- Migracje danych są testowane z poprzednim wspieranym wydaniem. Przed zmianą istnieje strategia kopii zapasowej i odzyskania działania.
- Powrót do starszej binarki nie oznacza automatycznie możliwości odczytu nowszej bazy. Procedura odtworzenia uwzględnia wersję danych, klucze i zgodność polityk.
- Odtworzenie kopii nie może bez kontroli przywrócić zużytych zgód lub odwołanych sesji. Uprawnienia czasowe wymagają bezpiecznego unieważnienia albo ponownego uzgodnienia stanu.

Nie budujemy własnego automatycznego aktualizatora tylko dla wygody MVP. Konkretny kanał wydawniczy i okres wsparcia ustalimy przed pierwszym wydaniem.

## 9. Lekkość i wydajność jako kryteria pomiarowe

Przed utrwaleniem stosu mierzymy:

- rozmiar instalacji i liczbę wymaganych usług;
- czas startu CLI oraz gotowości brokera;
- pamięć i CPU w spoczynku oraz pod ustalonym obciążeniem;
- opóźnienia p50, p95 i p99 lokalnej polityki i całej operacji;
- osobno opóźnienia Jev, docelowego API i oczekiwania na człowieka;
- zachowanie przy dużych odpowiedziach, nasyceniu kolejek i długotrwałej pracy;
- przyrost danych audytowych i koszt usług zewnętrznych.

Budżety liczbowe ustalamy po prototypie, na opisanym sprzęcie i scenariuszu. Wcześniej omawiane liczby są hipotezami, nie zaakceptowanymi wymaganiami ani wynikami pomiarów. CI wykrywa regresje względem zatwierdzonej bazy pomiarowej.

Niezależnie od stosu obowiązują ograniczone kolejki, rozmiary komunikatów, współbieżność i czas oczekiwania. Preferujemy działanie zdarzeniowe zamiast niepotrzebnego pollingu. Przeciążenie nie może omijać kontroli dostępu.

## 10. Weryfikacja i etapy

### Przed wyborem stosu

- Opisać model zagrożeń, granice zaufania i docelową konfigurację MVP.
- Sprawdzić najważniejsze ryzyka krótkim prototypem, bez budowania całego produktu w kilku językach.
- Zmierzyć podstawowy przepływ, zależności i koszt dystrybucji.
- Zapisać decyzje wraz z dowodami i kompromisami.

### MVP

- Jeden model izolacji, jeden magazyn i jedna integracja operacyjna zgodnie z Product Vision v1.
- Testy polityki, zużycia zgód, współbieżności, replay, TTL i unieważniania.
- Testy nieprawidłowych wejść, wycieków testowych sekretów, SSRF oraz ograniczeń zasobów.
- Testy awarii Jev, magazynu, sieci i zapisu audytu.
- Powtarzalne budowanie, sprawdzona instalacja, aktualizacja i odzyskanie działania.
- Udokumentowane ograniczenia; brak deklaracji pełnego bezpieczeństwa na podstawie samych testów.

### Wersja produktu v1

- Izolacja projektów i środowisk, delegowanie oraz tożsamości CI.
- Dalsze adaptery, panel i operacyjne mechanizmy audytu zgodnie z wizją produktu.
- Pilotaż zespołowy, testy długotrwałe i niezależny przegląd bezpieczeństwa.
- Dodatkowe usługi, skalowanie lub wysoka dostępność tylko wtedy, gdy uzasadnia je obciążenie i wymagania użytkowników.

## 11. Otwarte decyzje

Do rozstrzygnięcia przed odpowiednim etapem pozostają:

- język i biblioteki rdzenia;
- pierwsza platforma i mechanizm izolacji;
- transport lokalny oraz uwierzytelnianie kanału administracyjnego;
- magazyn metadanych, format szyfrowania i cykl życia kluczy;
- kontrakt i warunki integracji Jev;
- format polityk oraz protokoły adapterów;
- kanały wydań i wspierane ścieżki migracji;
- budżety zasobów i wydajności;
- stos panelu i model wdrożenia zespołowego.

Zasada końcowa: najprostszy stos, który spełnia udokumentowane granice bezpieczeństwa i zmierzone potrzeby. Rozwiązania komplikujemy dopiero na podstawie dowodów, nie przewidywań.
