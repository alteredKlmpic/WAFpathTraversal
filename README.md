# Web Application Firewall (WAF) & DVWA Zaštita

Ovaj projekat predstavlja implementaciju prilagođenog **Web Application Firewall-a (WAF)** napisanog u Python-u (Flask) koji funkcioniše kao reverzni proksi (Reverse Proxy) ispred **DVWA (Damn Vulnerable Web Application)** aplikacije pokrenute unutar Docker kontejnera.

Glavni fokus projekta je presretanje saobraćaja, detekcija i blokiranje *Path Traversal* napada (uz sprečavanje bypass tehnika pomoću naprednog dekodiranja), kao i analiza stabilnosti i performansi celokupnog sistema pod visokim opterećenjem.

---

## 🏗️ Arhitektura Sistema

Sistem se bazira na troslojnoj arhitekturi izolacije saobraćaja:
1. **Klijent / Alat za testiranje (Curl, Siege, Browser):** Šalje HTTP zahteve isključivo ka WAF-u.
2. **WAF (Reverse Proxy):** Flask aplikacija koja sluša na portu `9000`. Presreće zahteve, vrši duboku inspekciju URL-ova, parametara i zaglavlja. Ako uoči maliciozni šablon, vraća `403 Forbidden`. Ako je zahtev čist, prosleđuje ga backendu.
3. **Backend (DVWA):** Docker kontejner koji radi na portu `8080`, potpuno izolovan od direktnog spoljnog pristupa.

---

## 🐋 Korak 1: Instalacija Docker-a i Docker Compose-a (Ubuntu/Debian)

Da biste podigli ranjivo okruženje (DVWA), potrebno je instalirati Docker prateći ove korake u terminalu:

```bash
# 1. Ažuriranje sistema i instalacija preduslova
sudo apt update
sudo apt install ca-certificates curl gnupg -y

# 2. Dodavanje zvaničnog Docker GPG ključa za verifikaciju paketa
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL [https://download.docker.com/linux/ubuntu/gpg](https://download.docker.com/linux/ubuntu/gpg) | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# 3. Dodavanje Docker skladišta u APT izvore
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] [https://download.docker.com/linux/ubuntu](https://download.docker.com/linux/ubuntu) \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 4. Instalacija Docker paketa i dodataka
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# 5. Konfiguracija dozvola (Pokretanje Dockera bez 'sudo' komande)
sudo usermod -aG docker $USER

---

## 📦 Korak 2: Instalacija i preuzimanje DVWA (Backend)

DVWA se pokreće unutar Docker kontejnera, što eliminiše potrebu za ručnim konfigurisanjem PHP-a i MySQL baze podataka na samom sistemu. Preuzimanje zvaničnog imidža vrši se automatski prilikom prvog pokretanja.

Preporučeni način za upravljanje kontejnerom je kreiranje `docker-compose.yml` fajla u korenu projekta radi lakše prenosivosti:

```yaml
version: '3.8'

services:
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa-container
    ports:
      - "8080:80"
    restart: always

## 🐍 Korak 3: Podešavanje Python Okruženja i Zavisnosti (Dependencies)

# Instalacija alata za virtuelna okruženja (ukoliko već nije instaliran)
sudo apt install python3-venv -y

# Kreiranje okruženja
python3 -m venv .venv

# Aktivacija virtuelnog okruženja
source .venv/bin/activate

# Instalacija neophodnih biblioteka
pip install Flask requests

## 🚀 Korak 4: Redosled i Način Pokretanja Sistema

# Pokretanje ranjive aplikacije
docker run -d -p 8080:80 --name dvwa-container vulnerables/web-dvwa

# Pokretanje WAF-a (mora u drugom terminalu)
source .venv/bin/activate
python main.py

## 🛠️ Korak 5: Inicijalizacija i Prvi Pristup

Otvorite vaš veb čitač (Browser) i pristupite aplikaciji isključivo preko WAF-a na adresi: http://127.0.0.1:9000.

Prijavite se na sistem koristeći podrazumevane kredencijale (Username: admin, Password: password).

Pošto se aplikacija pokreće prvi put unutar kontejnera, kliknite na dugme "Create / Reset Database" na dnu ekrana kako bi se inicijalizovala MySQL baza podataka.

U levom meniju podesite nivo bezbednosti na "DVWA Security" -> Low, čime je okruženje spremno za analizu ranjivosti i stres testiranje.

## 🔍 Korak 6: Testiranje i Verifikacija (WAF u akciji)

Za verifikaciju rada, analizu sesija i proveru performansi sistema pod opterećenjem, svi testovi se usmeravaju isključivo na port 9000 (WAF proxy).

Pre pokretanja ovih komandi u terminalu, pokupite vrednost PHPSESSID kolačića iz vašeg browsera (F12 -> Application -> Cookies).

Legitimni zahtevi (WAF propušta -> Status 200 OK)

    URL primer: http://127.0.0.1:9000/vulnerabilities/fi/?page=include.php

    Korišćenjem curl alata:
    curl -v -b "PHPSESSID=cookie; security=low" "http://127.0.0.1:9000/vulnerabilities/fi/?page=include.php"

Detektovani napadi (WAF blokira -> Status 403 Forbidden)

    Klasičan Path Traversal napad:
    curl -v -b "PHPSESSID=cookie; security=low" "http://127.0.0.1:9000/vulnerabilities/fi/?page=/etc/passwd"

