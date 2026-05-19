import requests
import urllib.request
import urllib.parse
from flask import Flask, request, Response

app = Flask(__name__)

veza_sa_dockerom = requests.Session()

app.config['SERVER_NAME'] = '127.0.0.1:9000' #waf
TARGET_URL = "http://127.0.0.1:80" #dvwa

commonPathTraversalWords = frozenset(["etc","passwd","proc","root","ssh","shadow","config","//",".."])
#TODO dodati white list za situacije poput http://testsite.com/get.php?f=list

def decoding(putanja):

    prevStr = ""
    currStr = toLowerCase(putanja)

    while prevStr != currStr:
        prevStr = currStr
        currStr = urllib.parse.unquote(currStr)

    return currStr

def toLowerCase(putanja):

    lowerCaseUrl = putanja.lower()
    return lowerCaseUrl

def checkCommonWords(putanja):

    if any(word in putanja for word in commonPathTraversalWords):
        return True
    else:
        return False


def checkExternalSite(putanja):

    isExternalSite = False

    if putanja.count("http") > 1 or putanja.count("https") > 1 or putanja.count("php") > 1:
        isExternalSite = True

    return isExternalSite

def checkPercent(putanja):

    if "%" in putanja:
        return True
    else:
        return False

def checkUrl(putanja):

    for char in putanja:
        if char.isupper():
            putanja = toLowerCase(putanja)
            break

    if checkPercent(putanja):
        putanja = decoding(putanja)

    if checkExternalSite(putanja) or checkCommonWords(putanja):
        return True

    # if any(word in putanja for word in commonPathTraversalWords):
    #     return True

    # if putanja.count("http") > 1 or putanja.count("https") > 1 or putanja.count("php") > 1:
    #     return True

    return False



def checkCookie():

    currCookie = request.cookies

    if not currCookie:
        return False

    strCookie = str(currCookie)
    strCookie = toLowerCase(strCookie)

    if checkPercent(strCookie):
        strCookie = decoding(strCookie)

    if checkExternalSite(strCookie) or checkCommonWords(strCookie):
        return True

    # if "%" in cookie:
    #     cookie = decoding(cookie)
    #
    # if any(word in cookie for word in commonPathTraversalWords):
    #     return True

    return False

def checkParametarValue(url):

    parsed_url = urllib.parse.urlparse(url)
    urlArgs = urllib.parse.parse_qs(parsed_url.query)

    for args in urlArgs.values():

        for singleVal in args:

            singleVal = toLowerCase(singleVal)

            if checkPercent(singleVal):
                singleVal = decoding(singleVal)

            if checkCommonWords(singleVal) or checkExternalSite(singleVal):
                return True

    return False

def proveri_saobracaj(putanja, parametri):
    """
    WAF logika za inspekciju saobraćaja.
    Ako detektuje '..' u putanji ili u bilo kom GET parametru, vraća True (Blokiraj).
    """

    if checkUrl(putanja) or checkCookie():
        return True

    if "=" in request.url and checkParametarValue(request.url):
        return True

    return False


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):

    parametri = request.args

    if proveri_saobracaj(path, parametri):
        # Ako je maliciozno, vraćamo 403 Forbidden i ispisujemo u konzoli
        print(f"\n[WAF DETEKCIJA] BLOKIRAN NAPAD! Putanja: /{path} | Parametri: {dict(parametri)}")
        return "403 Forbidden, WAF je blokirao napad", 403

    url = f"{TARGET_URL}/{path}"

    # ciscenje headera
    hederi = {key: value for key, value in request.headers.items() if key.lower() != 'host'}
    hederi = {key: value for key, value in hederi.items() if key.lower() != 'accept-encoding'}

    # slanje zahteva dokeru
    try:
        odgovor_od_dvwa = veza_sa_dockerom.request(
            method=request.method,
            url=url,
            headers=hederi,
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


    # response iz dokera korisniku
    response = Response(odgovor_od_dvwa.content, odgovor_od_dvwa.status_code)
    for key, value in odgovor_od_dvwa.headers.items():
        if key.lower() not in ['content-length', 'connection', 'transfer-encoding', 'content-encoding']:
            response.headers[key] = value

    return response


if __name__ == "__main__":
    print("[WAF] Pokrenut na http://127.0.0.1:9000 -> DVWA na portu 80")
    # Pokrećemo bez debug moda da PyCharm ne bi forsirao stare portove
    app.run(threaded=True, debug=False)