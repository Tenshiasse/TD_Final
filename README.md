# Analyse des avis et alertes ANSSI

Outil qui extrait les bulletins ANSSI (avis et alertes), recupere les CVE,
les enrichit avec les donnees MITRE (CVSS CWE) et FIRST (EPSS), consolide le
tout dans un CSV puis fait des visualisations et du machine learning.

## Donnees

Les donnees sont dans le dossier `data` avec les sous dossiers :
- `Avis` bulletins avis ANSSI
- `alertes` bulletins alertes ANSSI
- `mitre` infos CVE (CVSS CWE description produits)
- `first` infos EPSS

On travaille en local sur ces fichiers pour ne pas surcharger les serveurs.

Le CSV ne garde que les avis de 2024 et 2025 et toutes les alertes.

## Fichiers

- `extraction.py` lecture des bulletins et extraction des CVE
- `enrichissement.py` recuperation CVSS CWE EPSS pour une CVE
- `consolidation.py` construit le DataFrame et ecrit `donnees_consolidees.csv`
- `alertes.py` cree les mails d alerte pour les CVE critiques
- `notebook.ipynb` exploration visualisations et machine learning
- `notebook.html` export du notebook

## Lancer le projet

Se placer dans ce dossier puis :

```
python consolidation.py
python alertes.py
```

Puis ouvrir `notebook.ipynb` pour les analyses.

## Dependances

- pandas
- matplotlib
- scikit-learn
- feedparser

pip install pandas matplotlib scikit-learn feedparser requests jupyter
Le mode principal est local mais `extraction.py` contient aussi `extraire_rss`
qui montre l extraction des flux RSS ANSSI avec feedparser titre description date lien
elle n est pas appelee par defaut
