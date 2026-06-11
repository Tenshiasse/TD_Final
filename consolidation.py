import pandas as pd
import extraction
import enrichissement


def lien_bulletin(id_b, type_b):
    if type_b == "Alerte":
        return "https://www.cert.ssi.gouv.fr/alerte/" + id_b + "/"
    return "https://www.cert.ssi.gouv.fr/avis/" + id_b + "/"


# extraction des bulletins
avis = extraction.extraire("data/Avis", "Avis")
alertes = extraction.extraire("data/alertes", "Alerte")

# on garde seulement les avis recents 2024 et 2025
avis = [a for a in avis if a["date"][:4] in ["2024", "2025"]]

bulletins = avis + alertes

# une ligne par cve
lignes = []
for b in bulletins:
    for cve in b["cves"]:
        info = enrichissement.get_mitre(cve)
        epss = enrichissement.get_epss(cve)
        ligne = {}
        ligne["ID ANSSI"] = b["id"]
        ligne["Titre ANSSI"] = b["titre"]
        ligne["Type"] = b["type"]
        ligne["Date"] = b["date"]
        ligne["CVE"] = cve
        ligne["Lien"] = lien_bulletin(b["id"], b["type"])
        if info:
            ligne["Score CVSS"] = info["cvss"]
            ligne["Base Severity"] = info["severity"]
            ligne["CWE"] = info["cwe"]
            ligne["Description"] = info["description"]
            ligne["Editeur"] = info["vendor"]
            ligne["Produit"] = info["produit"]
            ligne["Versions"] = info["versions"]
        else:
            ligne["Score CVSS"] = "Non disponible"
            ligne["Base Severity"] = "Non disponible"
            ligne["CWE"] = "Non disponible"
            ligne["Description"] = "Non disponible"
            ligne["Editeur"] = "Non disponible"
            ligne["Produit"] = "Non disponible"
            ligne["Versions"] = ""
        ligne["Score EPSS"] = epss
        lignes.append(ligne)

df = pd.DataFrame(lignes)
df.to_csv("donnees_consolidees.csv", index=False, encoding="utf-8")
print("Nombre de lignes", len(df))
print(df.head())
