## IPK - DNS Lookup nástroj
# Informace
Nástroj sloužící pro dotazování DNS serverů.
# Omezení
Iterativní dotazování u DNS typu PTR je nefunkční.
# Překlad
 - Projekt lze přeložit příkazem **make**, který vytvoří spustitelný
   soubor (ipk-lookup).
 - Pomocí příkazu **make clean** lze odstranit objektové soubory
   a příkazem **make remove** navíc i spustitelné soubory.
# Použití
./ipk-lookup [-h]
./ipk-lookup -s server [-T timeout] [-t type] [-i] name
 - h (help) - volitelný parametr, při jeho zadání se vypíše nápověda a program se ukončí.
 - s (server) - povinný parametr, DNS server (IPv4 adresa), na který se budou odesílat dotazy.
 - T (timeout) - volitelný parametr, timeout (v sekundách) pro dotaz, výchozí hodnota 5 sekund.
 - t (type) - volitelný parametr, typ dotazovaného záznamu: A (výchozí), AAAA, NS, PTR, CNAME.
 - i (iterative) - volitelný parametr, vynucení iterativního způsobu rezoluce.
 - name - překládané doménové jméno, v případě parametru -t PTR program na vstupu naopak očekává IPv4 nebo IPv6 adresu.
