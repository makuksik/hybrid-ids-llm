Dokumentacja Uruchomienia Systemu NetSentinel IDS
System składa się z dwóch modułów: Frontendu uruchamianego w środowisku Docker oraz Backendowego sniffera uruchamianego natywnie w systemie hosta. Rozdzielenie to jest wymagane dla poprawnego działania przechwytywania pakietów przez bibliotekę Scapy w systemie Windows.

Wymagania systemowe
Docker Desktop.

Python w wersji 3.10 lub nowszej.

Sterownik Npcap (należy pobrać ze strony npcap.com i zainstalować z zaznaczoną opcją "Install Npcap in WinPcap API-compatible Mode").

Krok 1: Konfiguracja i uruchomienie Frontendu
Frontend korzysta z technologii Next.js i jest izolowany w kontenerze Docker.

Otwórz terminal w głównym katalogu projektu.

Zatrzymaj ewentualne działające kontenery poleceniem:
docker-compose down

Uruchom usługę interfejsu użytkownika:
docker-compose up frontend

Interfejs graficzny będzie dostępny w przeglądarce pod adresem: http://localhost:3000

Krok 2: Konfiguracja i uruchomienie Backendu
Backend musi zostać uruchomiony poza Dockerem, aby uzyskać bezpośredni dostęp do interfejsów sieciowych systemu operacyjnego.

Otwórz nowy terminal i przejdź do katalogu aplikacji backendowej:
cd backend/app

Zainstaluj wymagane zależności środowiska Python:
pip install -r requirements.txt

Uruchom serwer API poleceniem:
uvicorn main:app --host 127.0.0.1 --port 8000