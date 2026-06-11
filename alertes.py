import pandas as pd
from email.mime.text import MIMEText
import smtplib

df = pd.read_csv("donnees_consolidees.csv")

# on garde les vulnerabilites critiques
df["Score CVSS"] = pd.to_numeric(df["Score CVSS"], errors="coerce")
critiques = df[df["Score CVSS"] >= 9]


def creer_mail(ligne):
    sujet = "Alerte CVE critique " + ligne["CVE"]
    corps = "La vulnerabilite " + ligne["CVE"] + " affecte " + str(ligne["Produit"])
    corps += " de l editeur " + str(ligne["Editeur"]) + "\n"
    corps += "Score CVSS " + str(ligne["Score CVSS"]) + "\n"
    corps += "Pensez a mettre a jour le produit rapidement\n"
    corps += "Bulletin " + ligne["Lien"]
    return sujet, corps


# affichage des mails pour les 10 premieres vulnerabilites critiques
for i, ligne in critiques.head(10).iterrows():
    sujet, corps = creer_mail(ligne)
    msg = MIMEText(corps)
    msg["Subject"] = sujet
    print("=====")
    print("Sujet", sujet)
    print(corps)


# envoi de mail optionnel
def envoyer_mail(destinataire, sujet, corps):
    from_email = "votre_email@gmail.com"
    password = "mot_de_passe_application"
    msg = MIMEText(corps)
    msg["From"] = from_email
    msg["To"] = destinataire
    msg["Subject"] = sujet
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, destinataire, msg.as_string())
    server.quit()
