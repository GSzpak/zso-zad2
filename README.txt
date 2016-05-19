Sterownik implementuje pełną wersję rozwiązania (używającą bloku DMA).
Dla każdego urządzenia trzymany jest bufor DMA zakończony komendą JUMP -
przez odpowiednie operowanie CMD_WRITE_PTR działa on jak bufor cykliczny
dla bloku wczytywania poleceń.

Synchronizacja:
Do synchronizacji sterownik wykorzystuje rejestr COUNTER, wpisując do niego
na zmianę dwie flagi. W momencie wywołania fsync() urządzenie sprawdza,
która flaga jest obecnie w COUNTER (flaga_a), dodaje do bufora
polecenie wpisania flagi przeciwnej (flaga_b), a następnie zasypia,
oczekując na zdarzenie (wartość w COUNTER == flaga_b). Po wykonaniu polecenia
urządzenie wyzwala przerwanie NOTIFY i proces jest budzony.

Na tej samej kolejce zasypiają też procesy czekające na wolne miejsce w buforze
DMA - one także są budzone przez przerwanie NOTIFY.

Synchronizacja następuje także podczas operacji write, jeśli następuje zmiana
kontekstu - w wyżej opisany sposób nowy kontekst czeka, aż poprzedni
zakończy swoją pracę.