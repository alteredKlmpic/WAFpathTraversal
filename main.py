import requests
import urlib.parse
from flask import Flask, request, Response

app = Flask(__name__)

# Eksplicitno podešavamo SERVER_NAME u Flasku da ga nateramo na port 9000
app.config['SERVER_NAME'] = '127.0.0.1:9000'

# Gde se nalazi naša ranjiva aplikacija (Docker sada uspešno sluša na portu 80):
TARGET_URL = "http://127.0.0.1:80"

commonPathTraversalWords = frozenset(["etc","passwd","proc","root","ssh","shadow","config","//","..","main"])
#TODO dodati white list za situacije poput http://testsite.com/get.php?f=list

def decoding(putanja):

    prevStr = ""
    currStr = putanja

    while prevStr != currStr:
        prevStr = currStr
        currStr = urllib.parse.unquote(currStr)

    return currStr

def toLowerCase(putanja):

    lowerCaseUrl = putanja.lower()
    return lowerCaseUrl

def checkUrl(putanja):

    for char in putanja:
        if char.isupper():
            putanja = toLowerCase(putanja)
            break

    if "%" in putanja:
        putanja = decoding(putanja)

    if any(word in putanja for word in commonPathTraversalWords):
        return True

    if putanja.count("http") > 1 or putanja.count("https") > 1 or putanja.count("php") > 1:
        return True

    return False



def checkCookie():

    cookie = request.cookies.get("session_token")

    if "%" in cookie:
        cookie = decoding(cookie)

    if any(word in cookie for word in commonPathTraversalWords):
        return True

    return False

@app.route("/admin-panel")
def isAdmin():

    if session.get("is_admin") == True:
        return True
    else:
        return False

def proveri_saobracaj(putanja, parametri):
    """
    WAF logika za inspekciju saobraćaja.
    Ako detektuje '..' u putanji ili u bilo kom GET parametru, vraća True (Blokiraj).
    """

    if not isAdmin():
       if checkUrl(putanja) or checkCookie():
           return True



    return False


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    # Uzimamo parametre iz URL-a
    parametri = request.args

    # Pozivamo funkciju za proveru bezbednosti
    if proveri_saobracaj(path, parametri):
        # Ako je maliciozno, vraćamo 403 Forbidden i ispisujemo u konzoli
        print(f"\n[WAF DETEKCIJA] BLOKIRAN NAPAD! Putanja: /{path} | Parametri: {dict(parametri)}")
        return "<h1>403 Forbidden</h1><p>WAF je uspesno blokirao tvoj Path Traversal napad!</p>", 403

    # Ako je sve u redu, konstruišemo URL za Docker
    url = f"{TARGET_URL}/{path}"

    # Pravilno čišćenje zaglavlja
    zaglavlja = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
    zaglavlja = {k: v for k, v in zaglavlja.items() if k.lower() != 'accept-encoding'}

    # Slanje zahteva Docker aplikaciji na portu 80
    try:
        odgovor_od_dvwa = requests.request(
            method=request.method,
            url=url,
            headers=zaglavlja,
            params=parametri,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
    except requests.exceptions.ConnectionError:
        return "<h1>502 Bad Gateway</h1><p>WAF ne moze da komunicira sa Docker aplikacijom. Proveri da li je Docker pokrenut.</p>", 502

    # Vraćamo odgovor iz Dockera nazad korisniku u browser
    response = Response(odgovor_od_dvwa.content, odgovor_od_dvwa.status_code)
    for k, v in odgovor_od_dvwa.headers.items():
        if k.lower() not in ['content-length', 'connection', 'transfer-encoding', 'content-encoding']:
            response.headers[k] = v

    return response


if __name__ == "__main__":
    print("[WAF] Pokrenut na http://127.0.0.1:9000 -> Štiti DVWA na portu 80")
    # Pokrećemo bez debug moda da PyCharm ne bi forsirao stare portove
    app.run(threaded=True, debug=False)