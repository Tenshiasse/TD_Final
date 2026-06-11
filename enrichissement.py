import os
import json


def lire_json(chemin):
    with open(chemin, encoding="utf-8") as f:
        return json.load(f)


def get_mitre(cve):
    chemin = os.path.join("data", "mitre", cve)
    if not os.path.exists(chemin):
        return None
    data = lire_json(chemin)
    if "containers" not in data:
        return None
    cna = data["containers"]["cna"]

    # description
    description = "Non disponible"
    descs = cna.get("descriptions", [])
    if descs:
        description = descs[0].get("value", "Non disponible")

    # score cvss et severite
    # attention le champ peut etre cvssV3_1 ou cvssV3_0 ou absent
    cvss = "Non disponible"
    severity = "Non disponible"
    metrics = cna.get("metrics", [])
    if metrics:
        for m in metrics:
            for cle in ["cvssV3_1", "cvssV3_0"]:
                if cle in m:
                    cvss = m[cle].get("baseScore", "Non disponible")
                    severity = m[cle].get("baseSeverity", "Non disponible")
                    break

    # cwe
    cwe = "Non disponible"
    pbt = cna.get("problemTypes", [])
    if pbt and "descriptions" in pbt[0]:
        cwe = pbt[0]["descriptions"][0].get("cweId", "Non disponible")

    # produit affecte
    vendor = "Non disponible"
    produit = "Non disponible"
    versions = ""
    affected = cna.get("affected", [])
    if affected:
        vendor = affected[0].get("vendor", "Non disponible")
        produit = affected[0].get("product", "Non disponible")
        vs = []
        for v in affected[0].get("versions", []):
            if v.get("status") == "affected":
                vs.append(v.get("version", ""))
        versions = ", ".join(vs)

    res = {}
    res["cvss"] = cvss
    res["severity"] = severity
    res["cwe"] = cwe
    res["description"] = description
    res["vendor"] = vendor
    res["produit"] = produit
    res["versions"] = versions
    return res


def get_epss(cve):
    chemin = os.path.join("data", "first", cve)
    if not os.path.exists(chemin):
        return "Non disponible"
    data = lire_json(chemin)
    d = data.get("data", [])
    if d:
        return d[0].get("epss", "Non disponible")
    return "Non disponible"
