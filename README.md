# Cours Sécurité des Données

Projet pédagogique autour de la sécurité des données appliquée à des sauvegardes PostgreSQL.

Le dépôt combine trois briques :
- un notebook pour produire des dumps et des exports CSV ;
- un module Python pour chiffrer et déchiffrer des fichiers ;
- une application Streamlit pour piloter les traitements sans passer uniquement par le terminal.

L'objectif n'est pas de fournir une solution industrielle prête pour la production, mais de comprendre les mécanismes de chiffrement, les formats de clés, les certificats et les contraintes concrètes d'implémentation.

## Objectifs du projet

- manipuler des dumps PostgreSQL et des exports tabulaires ;
- expérimenter le chiffrement symétrique et asymétrique ;
- comprendre la différence entre clé publique, clé privée et certificat ;
- visualiser les traitements via une interface simple ;
- conserver un historique local des opérations de chiffrement et de déchiffrement.

## Fonctionnalités

### Notebook de préparation des données

Le notebook [chiffrement_donnees.ipynb](./chiffrement_donnees.ipynb) permet de :
- générer une sauvegarde de la base `cours_securite` ;
- exporter les tables au format CSV ;
- produire des fichiers de travail dans `backups/` et `csv_exports/`.

### Chiffrement symétrique

Le module [encryption_utils.py](./encryption_utils.py) prend en charge :
- `DES`
- `Triple DES`
- `AES`
- `Twofish`

Chaque chiffrement symétrique :
- dérive une clé depuis une phrase de passe ;
- écrit un fichier `.enc` dans le même dossier que le fichier source ;
- embarque les métadonnées utiles au déchiffrement ;
- mesure le temps d'exécution.

Le projet permet aussi le déchiffrement symétrique à partir de la phrase de passe d'origine.

### Chiffrement asymétrique

Le projet prend en charge :
- `RSA`
- `ECC`
- `Infrastructure à clé publique (ICP)` via certificat

Le principe utilisé est pédagogique et classique :
- une clé publique ou un certificat sert à protéger une clé de session ;
- le contenu du fichier est ensuite chiffré avec cette clé de session ;
- la clé privée correspondante est nécessaire pour le déchiffrement.

Le projet permet aussi le déchiffrement asymétrique à l'aide de la clé privée associée.

### Gestion locale des clés

Depuis l'application Streamlit, il est possible de :
- générer une paire de clés `RSA` ;
- générer une paire de clés `ECC` ;
- générer un certificat auto-signé `ICP RSA` ;
- générer un certificat auto-signé `ICP ECC` ;
- sélectionner une clé publique, une clé privée ou un certificat depuis une bibliothèque locale ;
- télécharger la clé publique, la clé privée et le certificat quand ils existent ;
- supprimer un jeu de clés local.

Les jeux de clés générés sont stockés dans `keys/`.

### Interface Streamlit

L'application [streamlit_app.py](./streamlit_app.py) permet de :
- parcourir les dossiers du projet ;
- sélectionner un fichier `.dump` à chiffrer ;
- sélectionner un fichier `.enc` à déchiffrer ;
- choisir le mode symétrique ou asymétrique ;
- générer ou réutiliser des clés et certificats locaux ;
- afficher le temps d'exécution de chaque opération ;
- consulter un historique local des transactions.

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
└── README.md
```

## Rôle des principaux fichiers

### `chiffrement_donnees.ipynb`

Prépare les données sources du projet :
- export de sauvegardes PostgreSQL ;
- export de tables en CSV ;
- génération des fichiers utilisés ensuite dans l'application.

### `encryption_utils.py`

Centralise la logique applicative :
- chiffrement symétrique ;
- chiffrement asymétrique ;
- déchiffrement symétrique ;
- déchiffrement asymétrique ;
- lecture du format `.enc` ;
- gestion locale des clés ;
- enregistrement de l'historique.

### `streamlit_app.py`

Expose l'interface graphique :
- chiffrement symétrique ;
- chiffrement asymétrique ;
- déchiffrement ;
- gestion des clés et certificats ;
- consultation de l'historique.

### `backups/`

Contient les dumps PostgreSQL utilisés dans les démonstrations et tests.

### `csv_exports/`

Contient les exports tabulaires issus du notebook.

### `keys/`

Contient les jeux de clés et certificats générés localement depuis l'interface.

### `encryption_history.json`

Fichier généré localement pour stocker l'historique des transactions.

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

### Chiffrer un dump en symétrique

1. Lancer Streamlit.
2. Choisir un dossier contenant un fichier `.dump`.
3. Ouvrir l'onglet `Symétrique`.
4. Sélectionner un algorithme.
5. Saisir et confirmer une phrase de passe.
6. Lancer le chiffrement.

### Chiffrer un dump en asymétrique

1. Lancer Streamlit.
2. Choisir un fichier `.dump`.
3. Ouvrir l'onglet `Asymétrique`.
4. Soit générer un jeu de clés local, soit utiliser un fichier externe.
5. Sélectionner une clé publique ou un certificat.
6. Lancer le chiffrement.

### Déchiffrer un fichier `.enc`

1. Choisir un dossier contenant un fichier `.enc`.
2. Ouvrir l'onglet `Déchiffrement`.
3. Sélectionner le fichier chiffré.
4. Fournir la phrase de passe si le fichier est symétrique.
5. Fournir la clé privée si le fichier est asymétrique.
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

Dans ce projet, `Twofish` est donc utilisé via :
- le module binaire `_twofish` ;
- `ctypes` pour appeler les fonctions natives ;
- `importlib.util.find_spec` pour localiser l'extension compilée.

Cela permet de conserver l'algorithme `Twofish` dans l'application malgré la fragilité du wrapper Python fourni par la dépendance.

## Limites et précautions

- `DES` et `Triple DES` sont conservés pour des raisons pédagogiques, pas comme recommandations modernes.
- `AES` reste la référence symétrique la plus solide du projet.
- Les clés privées générées localement doivent être protégées et ne doivent pas être partagées.
- La perte d'une clé privée ou d'une phrase de passe rend le déchiffrement impossible.
- Les fichiers générés localement comme `keys/` et `encryption_history.json` sont exclus du dépôt via `.gitignore`.

## Flux logique du projet

1. Le notebook produit les données sources.
2. Les dumps sont stockés dans `backups/`.
3. Streamlit permet de chiffrer ou déchiffrer les fichiers.
4. `encryption_utils.py` applique la logique cryptographique.
5. Les résultats sont écrits dans le même dossier que le fichier d'origine.
6. L'historique local enregistre les opérations effectuées.

## Pistes pédagogiques couvertes

- différence entre chiffrement symétrique et asymétrique ;
- rôle d'une clé publique ;
- rôle d'une clé privée ;
- usage d'un certificat dans une logique ICP ;
- impact du choix de l'algorithme ;
- importance des métadonnées pour le déchiffrement ;
- dépendance entre robustesse cryptographique et qualité des bibliothèques utilisées.
