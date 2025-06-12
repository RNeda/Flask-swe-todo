# Flask tutorial
## Opis problema
Ovaj projekat predstavlja jednostavnu To-Do aplikaciju razvijenu korišćenjem Flask framework-a. Kroz ovu aplikaciju prikazane su osnovne mogućnosti Flask-a, uključujući rad sa rutama, formama i sesijama. Aplikacija omogućava registraciju i prijavu korisnika, nakon čega autentifikovani korisnici mogu da kreiraju svoju To-Do listu. Ulogovani korisnici imaju mogućnost dodavanja, uređivanja i brisanja zadataka.

## Šta je Flask?
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

### Konkurentska rešenja
Iako je Flask moćan i često korišćen framework, važno je znati da postoje i druga konkurentska rešenja za razvoj web aplikacija, kao što je Django. Flask je mikro-framework koji dolazi sa minimalnim skupom ugrađenih funkcionalnosti i pruža veliku fleksibilnost pri razvoju, dok je Django full-stack framework koji uključuje mnoge gotove alate i striktno definisanu strukturu projekta. Django je pogodan za veće i kompleksnije aplikacije koje zahtevaju brzu implementaciju sigurnosti, autentifikacije, ORM-a i drugih funkcionalnosti „iz kutije“. Sa druge strane, Flask omogućava potpunu kontrolu nad arhitekturom aplikacije, pa je idealan za male i srednje projekte, brze prototipe i sve situacije kada je potrebna veća sloboda u izboru biblioteka i strukture koda. Takođe, zbog svoje jednostavnosti i intuitivnog API-ja, Flask je odličan izbor za početnike koji tek ulaze u svet web developmenta. Ukratko, ako je cilj brza i jednostavna implementacija sa visokim nivoom prilagodljivosti – Flask je pravi izbor. Dok je Django bolja opcija kada želimo kompletno rešenje za kompleksne aplikacije.


## Instalacija Flask-a, kreiranje projekta i njegova struktura
Za razvoj Flask aplikacija koristi se Python i VS Code kao okruženje. U nastavku su opisani svi koraci potrebni za postavljanje projekta od nule:
### Preduslovi
Pre keiranja projekta podrazumeva se da imamo instaliran Python (ukoliko nije instaliran može se preuzeti na [https://www.python.org/downloads/](https://www.python.org/downloads/)). Takođe treba proveiti da li je *pip* instaliran uz python.
### Kreiranje projekta u VS Code
- Napraviti novi folder (npr. flask_app) i otvoriti ga u VS Code-u
- Otvoriti Terminal u VS Code-u i uneti sledeće komande:

za instalaciju vituelnog okružena
```
pip install virtualenv 
```
za kreiranje vituelnog okružena
```
virtualenv env 
```
aktivacija virtuelnog okruženja na windows-u. Nakon izvršenja ove komande na početku linije u teminalu treba da se pojavi (env)
```
env\Scripts\activate
```
instalirati flask i ostale bitne pakete koji će biti objašnjeni u nastavku
```
pip install flask 
pip install flask-sqlalchemy
pip install flask-wtf
pip install flask-login
pip install email-validator
```
- napaviti fajl app.py u glavnom folderu i dodati sledeći kod (hello world app)
```
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run(debug=True)
```
- Pokrenuti aplikaciju komandom u teminalu ```python app.py``` i otvoriti u pregledaču na adresi http://localhost:5000
- Kada smo se uverili da test aplikacija uspešno radi, u folderu aplikacije napravimo dva nova foldera:
  - static/ – za statički sadržaj (CSS, JS, slike, audio, video…)
  - templates/ – za HTML fajlove (koji se dinamički generišu)
- Unutar static/ foldera mogu se dalje organizovati fajlovi tako što se naprave podfolderi za css, js, slike..
- Odatle dalje možemo nadograđivati našu aplikaciju svime što je potebno

### Templates i static
Template fajlovi u Flask-u su HTML datoteke koje se koriste za kreiranje dinamičkih web stranica. Flask koristi Jinja2 – moćan šablonski mehanizam koji omogućava ugrađivanje Python logike unutar HTML fajlova. Statički fajlovi poput CSS-a, JavaScript-a i slika čuvaju se odvojeno (u static folderu).
Jedna od najkorisnijih osobina Flask-a je mogućnost da renderuje HTML pomoću funkcije *render_template()* iz Jinja2. Umesto da iz ruta vraćamo običan tekst, možemo dinamički prikazivati HTML stranice. *Render_template* treba importovati u app.py.
```
from flask import Flask, render_template
```
```
@app.route('/', methods=['POST', 'GET'])
def hellopage():
    return render_template('hellopage.html')
```
### Jinja2 za dinamičko generisanje stranica i nasleđivanje šablona
Flask koristi Jinja2 kao alat za dinamičko generisanje HTML stranica. To znači da možemo u naše HTML fajlove ubaciti Python logiku, kao što su petlje i uslovi. Na taj način ne pišemo isti HTML više puta, već ga 'šablonizujemo' i menjamo sadržaj u zavisnosti od podataka koje prosledimo iz backend-a. Kao što je već rečeno, u templates/ folder stavljamo HTML fajlove, a u Python ruti koristimo *render_template()* da ih prikažemo.
Unutar HTML-a koristimo posebne oznake:
- {{ }} za prikaz promenljivih (npr: {{ ime }})
- {% %} za logiku, poput for petlje ili if uslova

Templating sa Jinja2 nam štedi vreme, jer ne moramo da pišemo isti HTML više puta, već jedan šablon koristimo za prikaz različitih podataka.
Umesto da ponavljamo ceo HTML u svakom fajlu, pomoću Jinja2 možemo da nasleđujemo osnovni šablon i menjamo samo određene delove. Ovo se radi pomoću blokova i funkcioniše tako što u osnovnom HTML fajlu (base.html) definišemo blokove pomoću *{% block naziv_bloka %} … {% endblock%}*. Onda u drugom HTML fajlu (npr index.html) na početku stavimo *{% extends “base.html” %}*, dodamo blokove iz base.html I popunjavamo one koje želimo da izmenimo. Prednost je to što sve što se nalazi izvan bloka ostaje isto na svakoj stranici (zaglavlje, footer itd), a samo sadržaj unutar bloka se menja – što čini kod čistijim i lakšim za održavanje. Ovo je veoma koristan mehanizam kada pravimo više stranica sa istim izgledom, ali različitim sadržajem.
Jednostavan prime base.html koju će nasleđivati drugi HTML fajlovi
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/main.css') }}">
    {% block head %}{% endblock %}
</head>
<body>
    {% block body %}{% endblock %}
</body>
</html>

```
Primer index.html koji nasleđuje base.html. Unutar blokova head i body možemo dodavati sve ono što će biti jedinstveno za tu stranicu.
```
{% extends 'base.html' %}

{% block head %}
{% endblock %}

{% block body %}
{% endblock %}
```

Kao što je već rečeno, statički fajlovi koji se ne menjaju tokom izvršavanja aplikacije kao što su css, js, slike itd. čuvaju se u static folderu. U HTML fajlovima se statičkim fajlovima pristupa pomoću *url_for()* funkcije, kao što se može videti u base.html hederu. 
```
<link rel=”stylesheet” href=”{{  url_for(‘static’, filename=’css/main.css’) }}”>
``` 
Flask automatski servira fajlove iz foldera static, zato je važno da ih tamo pravilno organizujemo (npr. posebni podfolderi za css, js, images i sl). Ovo omogućava da aplikacija izgleda moderno i interaktivno.

### Rutiranje
Rutiranje aplikacije znači mapiranje URLa na određenu funkciju koja obrađuje potrebnu logiku za taj URL. Flask ima veoma jednostavan sistem rutiranja – rute se definišu pomoću dekoratora  *@app.route()* koji povezuju URL-ove sa Python funkcijama, što znatno olakšava kontrolu toka aplikacije. Kao parameter dekoratora navodimo konkretnu rutu koju želimo da vežemo za funkciju koja se nalazi ispod ovog dekoratora. Moguće je kroz URL poslati I dinamičke podatke I to tako što ćemo koristiti promenljivu u samom URL-u. Da bi dodali promenljivu u URL, koristi se *<variable_name>* pravilo. Funkcija zatim dobija *<variable_name>* kao argument sa tom ključnom reči. Dodatno može se specificirati tip promenljive navođenjem tipa pre imena promenljive: *<tip:variable_name>*.  Tip može da bude string, int, float, path, uuid.
Dodatno ako pored same rute dodamo I *methods=[‘POST’,GET’]*, možemo da podesimo koje metode će prihvatiti naša ruta.
```
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
  #definišemo dalje metodu
```

### Baza podataka i njena konfiguracija
Flask nema ugrađen mehanizam za rad sa bazama podataka, pa se oslanja na SQLAlchemy – moćnu biblioteku koja olakšava rad sa bazama. SQLAlchemy pruža Object Relational Mapper (ORM), što omogućava programerima da rade sa bazama koristeći Python kod umesto raw SQL-a.
Ovo donosi nekoliko prednosti:
- Pojednostavljuje upravljanje bazom podataka
- Poboljšava bezbednost
- Podržava više sistema baza podataka kao što su SQLite, MySQL i PostgreSQL
- Lako se integriše sa Flask-om putem ekstenzije Flask-SQLAlchemy

Već na samom početku ovog tutorijala je instalirana SQLAlchemy ekstenzija pomoću ```pip install flask-sqlalchemy```
Kako bismo kreirali bazu neophodno je da importujemo SQLAlchemy u app.py, postavimo sqlite konfiguraciju I kreiramo instance baze. Nakon inicijalizovanja baze I kreiranja njene instance neophodno je da napravimo modele koji će omogućiti komunikaciju sa bazom.
```
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os 

file_path = os.path.abspath(os.getcwd())+"/baza.db" 

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+file_path 
db = SQLAlchemy(app)
```

### Modeli
U Flasku, modeli predstavljaju strukturu podataka i omogućavaju rad sa bazom podataka. Oni omogućavaju programerima da komuniciraju sa bazom koristeći objektno-orijentisano programiranje, umesto da pišu raw SQL upite. Modeli pojednostavljuju rad sa bazom tako što pretvaraju tabele u Python klase, a redove iz baze u objekte. Na taj način, definiše se kako se podaci čuvaju, preuzimaju i upravljaju u aplikaciji pomoću ORM-a (Object Relational Mapping). Modeli u Flasku mogu da rade sa različitim bazama podataka, kao što su SQL, SQLite i mnoge druge.
```
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return '<Task %r>' % self.id

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('Todo', backref='author', lazy=True)

    def __repr__(self):
        return '<user %r>' % self.id
```
Kada smo kreirali modele sa svim neophodnim parametrima za svaku kolonu u tabeli, treba kreirati samu bazu podataka. To se radi tako što se u delu gde se pokreće aplikacija doda *db.create_all()*
```
if(__name__) == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
```

### CRUD operacije
Nakon što su modeli baze kreirani pomoću SQLAlchemy-a u Flask aplikaciji, možemo da implementiramo CRUD operacije (Create, Read, Update, Delete) kako bismo upravljali podacima. SQLAlchemy čini ove operacije intuitivnim i efikasnim, jer omogućava rad sa bazom koristeći Python objekte umesto direktnih SQL upita.

Deo koda za funkciju koja kreira novi objekat:
```
if request.method == 'POST':
        task_content = request.form['content']
        new_task = Todo(content=task_content, user_id=current_user.id)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect(url_for('index'))
        except:
            return 'There was an issue adding your task'
```
Brisanje objekta:
```
@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return 'There was a problem deleting that task'
```
Ažuriranje objekta:
```
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    task = Todo.query.get_or_404(id)

    if request.method == 'POST':
        task.content = request.form['content']

        try:
            db.session.commit()
            return redirect(url_for('index'))
        except:
            return 'There was an issue updating your task'

    else:
        return render_template('update.html', task=task)
```

### Flask-WTF
Flask-WTF je ekstenzija za Flask koja integriše biblioteku WTForms, olakšavajući kreiranje i validaciju formi u Flask aplikacijama. Omogućava strukturisan način za pravljenje formi, njihovu validaciju i prikazivanje u HTML-u.
Neke od ključnih karakteristika Flask-WTF-a su:
- Bezbedno upravljanje formama – Automatski upravlja CSRF zaštitom kako bi se sprečila neautorizovana slanja formi.
- Jednostavno prikazivanje formi – Podržava različite tipove polja kao što su tekstualna polja, čekboksovi i padajuće liste, omogućavajući laku integraciju u HTML.
- Ugrađena validacija – Podrška za obavezna polja, ograničenja dužine, provere obrasca (pattern matching), kao i prilagođene validacije.
- Otpremanje fajlova – Omogućava korisnicima da lako otpremaju fajlove putem forme.

Flask-WTF je instaliran na početku tutorijala komandom
```pip install flask-WTF ```
U Flask-WTF, forme se definišu kao klase koje nasleđuju *FlaskForm* klasu. Polja se deklarišu kao promenljive unutar klase, što čini proces pravljenja formi jednostavnim i organizovanim.
Najčešće korišćeni WTForms tipovi polja:
- *StringField*: Tekstualno polje za unos stringova
- *PasswordField*: Polje za unos lozinke
- *BooleanField*: Čekboks za izbor između tačno/netačno (True/False)
- *DecimalField*: Polje za unos decimalnih vrednosti
- *RadioField*: Grupa radio dugmadi za izbor jedne opcije
- *SelectField*: Padajuća lista za izbor jedne vrednosti
- *TextAreaField*: Višelinijsko tekstualno polje
- *FileField*: Polje za otpremanje fajlova

*form.hidden_tag()* koji se koristi u HTML-u, u Flask-WTF automatski generiše sva skrivena polja forme, uključujući CSRF token, čime omogućava sigurnu i potpunu obradu forme bez potrebe za ručnim dodavanjem tih polja. Ovo olakšava rad sa skrivenim podacima i poboljšava zaštitu od CSRF napada
```
#Register forma
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=25)])
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4)])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(), EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

#Login forma
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')
```

