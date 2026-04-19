# Cours Sécurité des Données

Projet pédagogique autour du chiffrement de fichiers, appliqué à des dumps PostgreSQL et à d'autres fichiers de travail produits pendant le cours.

Le dépôt réunit trois briques :
- un notebook pour préparer des données ;
- un module Python qui chiffre et déchiffre des fichiers ;
- une application Streamlit qui guide l'utilisateur pas à pas.

L'objectif n'est pas de fournir un outil de production, mais de comprendre concrètement :
- le chiffrement symétrique ;
- le chiffrement asymétrique ;
- la différence entre clé publique, clé privée et certificat ;
- le rôle des métadonnées et de l'historique ;
- les limites réelles d'une implémentation pédagogique.

## Objectifs

- manipuler des dumps PostgreSQL et des exports tabulaires ;
- chiffrer et déchiffrer différents types de fichiers ;
- comparer plusieurs algorithmes symétriques et asymétriques ;
- apprendre à générer, stocker et réutiliser des clés ;
- suivre les traitements depuis une interface simple ;
- observer le temps d'exécution et l'historique des opérations.

## Fonctionnalités

### Notebook de préparation

Le notebook [chiffrement_donnees.ipynb](./chiffrement_donnees.ipynb) permet de :
- générer une sauvegarde de la base `cours_securite` ;
- exporter des tables en CSV ;
- produire des fichiers de travail dans `backups/` et `csv_exports/`.

### Chiffrement symétrique

Le projet prend en charge :
- `DES`
- `Triple DES`
- `AES`
- `Twofish`

Principe :
- une phrase de passe est fournie par l'utilisateur ;
- une clé est dérivée à partir de cette phrase de passe ;
- le fichier est chiffré dans le même dossier que le fichier source ;
- le déchiffrement nécessite la même phrase de passe.

Chaque opération enregistre aussi :
- les métadonnées utiles ;
- le temps d'exécution ;
- une entrée dans l'historique local.

### Chiffrement asymétrique

Le projet prend en charge :
- `RSA`
- `ECC`
- `Infrastructure à clé publique (ICP)` via certificat

Principe :
- une clé publique ou un certificat sert à chiffrer ;
- la clé privée correspondante sert à déchiffrer ;
- l'application chiffre le contenu du fichier avec une clé de session, puis protège cette clé avec le matériel asymétrique.

Le projet permet aussi le déchiffrement asymétrique à l'aide de la clé privée adaptée.

### Gestion locale des clés et certificats

Depuis l'application Streamlit, il est possible de :
- générer une paire de clés `RSA` ;
- générer une paire de clés `ECC` ;
- générer un certificat auto-signé `ICP RSA` ;
- générer un certificat auto-signé `ICP ECC` ;
- consulter la bibliothèque locale des jeux de clés ;
- réutiliser une clé publique, une clé privée ou un certificat ;
- télécharger les fichiers générés ;
- supprimer un jeu de clés local.

Les éléments générés sont stockés dans `keys/`.

### Interface Streamlit

L'application [streamlit_app.py](./streamlit_app.py) permet de :
- parcourir les dossiers du projet ;
- sélectionner n'importe quel fichier source à chiffrer ;
- sélectionner un fichier `.enc` à déchiffrer ;
- choisir un chiffrement symétrique ou asymétrique ;
- générer ou charger des clés et certificats ;
- suivre des étapes pédagogiques directement dans l'interface ;
- afficher le temps d'exécution de chaque action ;
- consulter l'historique local des transactions.

### Historique des transactions

Chaque chiffrement et chaque déchiffrement réussi est enregistré dans `encryption_history.json` avec :
- la date ;
- l'opération ;
- la famille de chiffrement ;
- l'algorithme ;
- le fichier source ;
- le fichier de sortie ;
- la taille du fichier source ;
- le temps d'exécution.

## Structure du dépôt

```text
cours_securite/
├── chiffrement_donnees.ipynb
├── encryption_utils.py
├── streamlit_app.py
├── requirements.txt
├── environment.yml
├── backups/
├── csv_exports/
├── keys/
├── encryption_history.json
└── README.md
```

## Rôle des principaux fichiers

### `chiffrement_donnees.ipynb`

Prépare les données sources du projet :
- export de sauvegardes PostgreSQL ;
- export de tables en CSV ;
- génération de fichiers utilisés ensuite dans l'application.

### `encryption_utils.py`

Centralise la logique métier :
- chiffrement symétrique ;
- chiffrement asymétrique ;
- déchiffrement symétrique ;
- déchiffrement asymétrique ;
- lecture du format `.enc` ;
- gestion locale des clés ;
- enregistrement de l'historique.

### `streamlit_app.py`

Expose l'interface graphique :
- navigation dans les dossiers ;
- sélection du fichier à chiffrer ou à déchiffrer ;
- parcours pédagogique par étapes ;
- chiffrement symétrique ;
- chiffrement asymétrique ;
- déchiffrement ;
- gestion des clés et certificats ;
- historique des transactions.

### `backups/`

Contient les dumps PostgreSQL utilisés dans les démonstrations et les tests.

### `csv_exports/`

Contient les exports tabulaires issus du notebook.

### `keys/`

Contient les jeux de clés et certificats générés localement depuis l'interface.

### `encryption_history.json`

Fichier généré localement pour stocker l'historique des opérations.

## Installation

### Option conda

```bash
conda env create -f environment.yml
conda activate cours_securite
```

### Option pip

```bash
pip install -r requirements.txt
```

## Lancement

### Notebook

```bash
jupyter lab
```

### Application Streamlit

```bash
streamlit run streamlit_app.py
```

## Utilisation rapide

### Chiffrer un fichier en symétrique

1. Lancer Streamlit.
2. Choisir un dossier contenant un fichier source.
3. Sélectionner le fichier dans la barre latérale.
4. Ouvrir l'onglet `Symétrique`.
5. Choisir un algorithme.
6. Saisir et confirmer une phrase de passe.
7. Lancer le chiffrement.

### Chiffrer un fichier en asymétrique

1. Lancer Streamlit.
2. Choisir un dossier contenant un fichier source.
3. Sélectionner le fichier dans la barre latérale.
4. Ouvrir l'onglet `Asymétrique`.
5. Choisir `RSA`, `ECC` ou `ICP`.
6. Générer un jeu de clés local ou charger une clé publique / un certificat.
7. Lancer le chiffrement.

### Déchiffrer un fichier `.enc`

1. Choisir un dossier contenant un fichier `.enc`.
2. Sélectionner le fichier chiffré dans la barre latérale.
3. Ouvrir l'onglet `Déchiffrement`.
4. Lire le type détecté par l'application.
5. Fournir la phrase de passe ou la clé privée selon le cas.
6. Lancer le déchiffrement.

## Dépendances principales

- `cryptography`
- `pycryptodome`
- `twofish`
- `streamlit`
- `pandas`
- `jupyterlab`

## Compatibilité Python

Le projet est prévu pour fonctionner avec une version récente de Python, notamment Python `3.13`.

### Point d'attention sur `Twofish`

Le paquet `twofish` installe bien son extension compilée, mais son wrapper Python standard repose sur `imp`, un module supprimé dans les versions récentes de Python.

Dans ce projet, `Twofish` est utilisé via :
- le module binaire `_twofish` ;
- `ctypes` pour appeler les fonctions natives ;
- `importlib.util.find_spec` pour localiser l'extension compilée.

Cela permet de conserver `Twofish` dans le projet malgré la fragilité du wrapper Python fourni par la dépendance.

## Limites et précautions

- `DES` et `Triple DES` sont conservés pour des raisons pédagogiques, pas comme recommandations modernes.
- `AES` reste la référence symétrique la plus solide du projet.
- Les clés privées générées localement doivent être protégées et ne doivent pas être partagées.
- La perte d'une clé privée ou d'une phrase de passe rend le déchiffrement impossible.
- Les fichiers générés localement comme `keys/` et `encryption_history.json` sont exclus du dépôt via `.gitignore`.
- Le projet est pensé pour l'apprentissage et la démonstration, pas pour un usage de production.

## Flux logique

1. Le notebook produit des fichiers de travail.
2. L'application Streamlit permet de choisir un fichier source ou un fichier `.enc`.
3. L'utilisateur choisit la méthode de chiffrement ou de déchiffrement.
4. `encryption_utils.py` applique la logique cryptographique.
5. Le résultat est écrit dans le même dossier que le fichier d'origine.
6. L'historique local garde la trace des opérations réalisées.

## Notions pédagogiques couvertes

- différence entre chiffrement symétrique et asymétrique ;
- rôle d'une phrase de passe ;
- rôle d'une clé publique ;
- rôle d'une clé privée ;
- rôle d'un certificat dans une logique ICP ;
- impact du choix de l'algorithme ;
- importance des métadonnées pour le déchiffrement ;
- observation du temps d'exécution ;
- gestion concrète de clés dans une application.
