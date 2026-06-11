import os
import json
import feedparser


def lire_bulletin(chemin):
    with open(chemin, encoding="utf-8") as f:
        data = json.load(f)
    return data


def get_date(data):
    # on prend la date de la premiere revision
    revs = data.get("revisions")
    if revs:
        return revs[0].get("revision_date", "")[:10]
    return ""


def get_cves(data):
    cves = []
    for c in data.get("cves", []):
        cves.append(c["name"])
    return cves


def extraire(dossier, type_bulletin):
    resultats = []
    for nom in os.listdir(dossier):
        data = lire_bulletin(os.path.join(dossier, nom))
        b = {}
        b["id"] = data.get("reference", nom)
        b["titre"] = data.get("title", "")
        b["type"] = type_bulletin
        b["date"] = get_date(data)
        b["cves"] = get_cves(data)
        resultats.append(b)
    return resultats


# extraction des flux rss ANSSI en ligne
# on travaille en local par defaut donc cette fonction n est pas appelee
def extraire_rss(url):
    flux = feedparser.parse(url)
    resultats = []
    for entry in flux.entries:
        b = {}
        b["titre"] = entry.title
        b["description"] = entry.description
        b["date"] = entry.published
        b["lien"] = entry.link
        resultats.append(b)
    return resultats


# exemple url avis https://www.cert.ssi.gouv.fr/avis/feed/
# exemple url alertes https://www.cert.ssi.gouv.fr/alerte/feed/
