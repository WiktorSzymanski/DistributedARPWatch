# Wersja rozproszona narzędzia `arpwatch(8)`

## Zawartość plików źródłowych
---
    `server.c` - kod serwera odbierającego wiadomości o odebraniu ramki arp przez programy klientów. Generuje pliki `disarp.log` i `disarp.table`. Plik `table` zawiera aktualną tabelę adresów IP i odpowiadających im adresów MAC, z kolei plik 'log' zawiera logi (te same które program wypisuje na standardowe wyjście).
`arp_catch.c` - kod klienta, przechwytuje ramki ARP i przesyła je do serwera.

## Kompilacja
---
###### Serwer
``` bash
gcc -Wall server.c -o server
```

###### Klient
    Wymagana jest biblioteka `libpcap-devel`.
``` bash
gcc -Wall arp_catch.c -o arp_catch -lpcap
```

## Sposób uruchomienia
---
##### Serwer
``` bash
./server
```

##### Klient
    Należy odpalić z uprawnieniami `root`.
``` bash
./arp_catch <INTERFACE> <SERVER_ADDRES> <SERVER_PORT>
```
