import requests
from flask import Flask, request, Response

app = Flask(__name__)

# Gde se nalazi naša ranjiva aplikacija koju smo upravo podigli u Dockeru:
TARGET_URL = "http://localhost:8001"


def proveri_saobracaj(putanja, parametri):
    """
    OVDE TVOJ KOLEGA PIŠE SVOJ DEO (Blacklist, Regex, Logovanje).
    Za sada, ova funkcija samo propušta sve (vraća False da nije maliciozno).
    """
    # Primer kako će kolega to proveravati:
    # if ".." in putanja or ".." in str(parametri):
    #     return True
    return False


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])

def proxy(path):
    # Uzimamo parametre iz URL-a
    parametri = request.args

    # Pozivamo funkciju za proveru bezbednosti (deo tvog kolege)
    if proveri_saobracaj(path, parametri):
        # Ako je maliciozno, vraćamo 403 i ne šaljemo zahtev Dockeru
        return "403 Forbidden: WAF blokirao Path Traversal napad!", 403

    # Ako je sve u redu, prosleđujemo zahtev na DVWA u Dockeru
    url = f"{TARGET_URL}/{path}"

    # KLJUČNA IZMENA: Uzimamo tvoja zaglavlja, ali izbacujemo 'accept-encoding'
    # Na taj način primoravamo Docker da nam vrati čist tekst umesto Gzip-a
    zaglavlja = {k: v for k, v in request.headers if k.lower() != 'host'}
    if 'accept-encoding' in [k.lower() for k in zaglavlja.keys()]:
        # Brišemo accept-encoding ako postoji
        zaglavlja = {k: v for k, v in zaglavlja.items() if k.lower() != 'accept-encoding'}

    odgovor_od_dvwa = requests.request(
        method=request.method,
        url=url,
        headers=zaglavlja,  # Šaljemo očišćena zaglavlja
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )

    # Vraćamo odgovor iz Dockera nazad korisniku u browser
    response = Response(odgovor_od_dvwa.content, odgovor_od_dvwa.status_code)
    for k, v in odgovor_od_dvwa.headers.items():
        if k.lower() not in ['content-length', 'connection', 'transfer-encoding', 'content-encoding']:
            response.headers[k] = v

    return response


if __name__ == "__main__":
    print("[WAF] Pokrenut na http://localhost:8080 -> Štiti aplikaciju na portu 8001")
    app.run(host="127.0.0.1", port=8080, threaded=True)