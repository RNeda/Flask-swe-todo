# Flask tutorial
## Opis problema
Ovaj projekat predstavlja jednostavnu To-Do aplikaciju razvijenu korišćenjem Flask framework-a. Kroz ovu aplikaciju prikazane su osnovne mogućnosti Flask-a, uključujući rad sa rutama, formama i sesijama. Aplikacija omogućava registraciju i prijavu korisnika, nakon čega autentifikovani korisnici mogu da kreiraju svoju To-Do listu. Ulogovani korisnici imaju mogućnost dodavanja, uređivanja i brisanja zadataka.

## ŠTA JE FLASK?
Flask je popularan, lightweight i fleksibilan web framework zasnovan na Python programskom jeziku. Spada u kategoriju mikro framework-a, što znači da dolazi sa minimalnim ugrađenim setom funkcionalnosti, ali omogućava lako proširivanje u skladu sa potrebama projekta. Idealan je za brzo razvijanje web aplikacija i REST API-ja, a zahvaljujući svojoj jednostavnosti i maloj početnoj složenosti, posebno je pogodan za početnike u web programiranju. Iako je odličan za manje projekte i brze prototipe, dovoljno je moćan i fleksibilan da se koristi i za razvoj kompleksnijih aplikacija.

### Ključne karakteristike Flask-a i zašto ga koristiti 
- Mikro framework - Flask je mikro framework, što znači da dolazi sa minimalnim ugrađenim setom funkcionalnosti. Nudi osnovne komponente neophodne za razvoj web aplikacija, poput definisanja ruta i rada sa HTTP zahtevima, ali ostavlja korisniku potpunu slobodu da samostalno bira dodatne biblioteke za funkcionalnosti kao što su autentifikacija, rad sa bazama podataka, validacija formi i slično.
- Jednostavnost - Flask je izuzetno lak za učenje i upotrebu, što ga čini idealnim za početnike. Pored toga, poseduje detaljnu dokumentaciju i aktivnu zajednicu koja dodatno olakšava učenje i rešavanje problema
- Fleksibilnost - Ne nameće strogu strukturu projekta, već omogućava programeru da sam organizuje kod i dodaje samo one funkcionalnosti koje su mu zaista potrebne.
- Zasnovan na moćnim bibliotekama - Flask je izgrađen na vrhu dve snažne biblioteke – Werkzeug i Jinja2, što ga čini stabilnim i proširivim rešenjem za web razvoj.
- Jinja2 templating engine - Flask koristi Jinja2 kao svoj sistem za šablone, što omogućava ubacivanje Python logike direktno u HTML fajlove i dinamičko generisanje sadržaja.
- Werkzeug - Za upravljanje HTTP zahtevima i odgovorima, Flask se oslanja na Werkzeug – robustan WSGI alat koji omogućava pouzdano upravljanje web server komunikacijom.
- Proširivost - Flask se lako prilagođava rastu projekta. Podržava integraciju sa brojnim popularnim bibliotekama i ekstenzijama, kao što su:
  - Flask-SQLAlchemy – za rad sa bazama podataka
  - Flask-Login – za autentifikaciju korisnika
  - Flask-WTF – za validaciju formi
  - Flask-Mail – za slanje e-mail poruka
- Baza podataka po izboru - Može se koristiti sa bilo kojom bazom podataka, uključujući i relacione (SQL) i nerelacione (NoSQL) baze.
- Frontend po izboru - Flask se može kombinovati sa bilo kojom frontend tehnologijom – kao što su Angular, React ili klasičan HTML/CSS/JS.

###Konkurentska rešenja
Iako je Flask moćan i često korišćen framework, važno je znati da postoje i druga konkurentska rešenja za razvoj web aplikacija, kao što je Django. Flask je mikro-framework koji dolazi sa minimalnim skupom ugrađenih funkcionalnosti i pruža veliku fleksibilnost pri razvoju, dok je Django full-stack framework koji uključuje mnoge gotove alate i striktno definisanu strukturu projekta. Django je pogodan za veće i kompleksnije aplikacije koje zahtevaju brzu implementaciju sigurnosti, autentifikacije, ORM-a i drugih funkcionalnosti „iz kutije“. Sa druge strane, Flask omogućava potpunu kontrolu nad arhitekturom aplikacije, pa je idealan za male i srednje projekte, brze prototipe i sve situacije kada je potrebna veća sloboda u izboru biblioteka i strukture koda. Takođe, zbog svoje jednostavnosti i intuitivnog API-ja, Flask je odličan izbor za početnike koji tek ulaze u svet web developmenta. Ukratko, ako je cilj brza i jednostavna implementacija sa visokim nivoom prilagodljivosti – Flask je pravi izbor. Dok je Django bolja opcija kada želimo kompletno rešenje za kompleksne aplikacije.


##Instalacija Flask-a, kreiranje projekta i njegova struktura
Za razvoj Flask aplikacija koristi se Python i VS Code kao okruženje. U nastavku su opisani svi koraci potrebni za postavljanje projekta od nule:
###Preduslovi
Pre keiranja projekta podrazumeva se da imamo instaliran Python (ukoliko nije instaliran može se preuzeti na [https://www.python.org/downloads/](https://www.python.org/downloads/). Takođe treba proveiti da li je *pip* instaliran uz python.
