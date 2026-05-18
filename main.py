import requests
from flask import Flask, request, Response

app = Flask(__name__)

veza_sa_dockerom = requests.Session()

app.config['SERVER_NAME'] = '127.0.0.1:9000' #waf
TARGET_URL = "http://127.0.0.1:80" #dvwa


def proveri_saobracaj(putanja, parametri):
    """
    WAF logika za inspekciju saobraćaja.
    Ako detektuje '..' u putanji ili u bilo kom GET parametru, vraća True (Blokiraj).
    """
    # 1. Provera same putanje u URL-u
    if ".." in putanja:
        return True

    # 2. Provera svih GET parametara (npr. ?page=../../)
    for kljuc, vrednost in parametri.items():
        if ".." in str(vrednost):
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
        return "403 Forbidden, WAF je blokirao napad", 403

    # Ako je sve u redu, konstruišemo URL za Docker
    url = f"{TARGET_URL}/{path}"

    # Pravilno čišćenje zaglavlja
    zaglavlja = {key: value for key, value in request.headers.items() if key.lower() != 'host'}
    zaglavlja = {key: value for key, value in zaglavlja.items() if key.lower() != 'accept-encoding'}

    # Slanje zahteva Docker aplikaciji na portu 80
    try:
        odgovor_od_dvwa = veza_sa_dockerom.request(
            method=request.method,
            url=url,
            headers=zaglavlja,
            params=parametri,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout = 5
        )
    except requests.exceptions.Timeout:
        return "504 Gateway Timeout, previse vremena je trebalo", 504
    except requests.exceptions.ConnectionError:
        return "502 Bad Gateway, problem u komunikaciji sa dockerom ", 502


    # Vraćamo odgovor iz Dockera nazad korisniku u browser
    response = Response(odgovor_od_dvwa.content, odgovor_od_dvwa.status_code)
    for key, value in odgovor_od_dvwa.headers.items():
        if key.lower() not in ['content-length', 'connection', 'transfer-encoding', 'content-encoding']:
            response.headers[key] = value

    return response


if __name__ == "__main__":
    print("[WAF] Pokrenut na http://127.0.0.1:9000 -> DVWA na portu 80")
    # Pokrećemo bez debug moda da PyCharm ne bi forsirao stare portove
    app.run(threaded=True, debug=False)