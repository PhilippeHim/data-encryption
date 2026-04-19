# Cours Sécurité des Données

Projet d'école consacré à l'apprentissage des formats standards de chiffrement avec Python, appliqués à des sauvegardes PostgreSQL et à l'export de données tabulaires.

L'objectif du projet est double :
- manipuler des dumps et des exports issus d'une base PostgreSQL ;
- expérimenter des mécanismes de chiffrement symétrique et asymétrique dans un cadre pédagogique, avec un bonus d'interface utilisateur via Streamlit.

## Esprit du projet

Ce dépôt a été conçu comme un terrain d'exploration pratique autour de la sécurité des données :
- création et export de sauvegardes PostgreSQL ;
- extraction de tables au format CSV ;
- chiffrement de fichiers avec plusieurs familles d'algorithmes ;
- mise à disposition d'une interface simple pour tester les traitements sans passer uniquement par le terminal.

Le but n'est pas de produire une solution industrielle prête à être déployée, mais de comprendre les principes, les formats, les dépendances Python et les limites des choix cryptographiques.

## Fonctionnalités

### 1. Notebook Jupyter

Le notebook [chiffrement_donnees.ipynb](./chiffrement_donnees.ipynb) permet de :
- exporter une sauvegarde complète de la base `cours_securite` ;
- exporter les tables de la base au format CSV ;
- générer des fichiers de travail dans des dossiers dédiés comme `backups/` et `csv_exports/`.

### 2. Chiffrement symétrique

Le moteur Python contenu dans [encryption_utils.py](./encryption_utils.py) prend en charge plusieurs formats de chiffrement symétrique :
- `DES`
- `Triple DES`
- `AES`
- `Twofish`

Dans le projet, chaque fichier chiffré est écrit dans le même répertoire que le fichier source, avec une extension `.enc` et des métadonnées embarquées.

### 3. Chiffrement asymétrique

Le projet propose également un mode de chiffrement asymétrique avec :
- `RSA`
- `ECC`
- `Infrastructure à clé publique (ICP)` via certificat

Le chiffrement asymétrique est pensé pour un usage pédagogique : la clé publique ou le certificat sert à protéger une clé de session utilisée ensuite pour le chiffrement du contenu.

### 4. Interface Streamlit

L'application [streamlit_app.py](./streamlit_app.py) apporte une couche visuelle au projet :
- sélection d'un dossier d'entrée ;
- sélection d'un fichier `.dump` ;
- choix du mode symétrique ou asymétrique ;
- choix de l'algorithme ;
- génération du fichier chiffré dans le même dossier que le dump source.

## Structure du dépôt

```text
cours_securite/
├── chiffrement_donnees.ipynb
├── encryption_utils.py
├── streamlit_app.py
├── environment.yml
├── requirements.txt
├── backups/
├── csv_exports/
└── README.md
```

## Architecture du projet

Le projet est organisé en trois couches qui se complètent :
- une couche d'exploration et de production de données avec le notebook ;
- une couche logique avec les fonctions Python de chiffrement ;
- une couche de démonstration avec l'interface Streamlit.

Autrement dit, le notebook produit les fichiers à manipuler, le module Python applique les algorithmes de chiffrement, et Streamlit sert d'interface pour piloter ces traitements sans écrire de commandes à la main.

## Fonctionnement interne des fichiers

### `chiffrement_donnees.ipynb`

Ce notebook permet l'export de dumps d'une base de donnée PostgreSQL.

Il contient des cellules destinées à :
- créer une sauvegarde complète de la base `cours_securite` dans le dossier `backups/` ;
- exporter les tables de la base au format CSV dans `csv_exports/` ;
- produire des artefacts concrets qui pourront ensuite être chiffrés.

Structure du schéma "cours_securite" :

cours_securite=# \dn
        List of schemas
    Name    |       Owner       
------------+-------------------
 production | philippe
 public     | pg_database_owner
 research   | philippe
(3 rows)

cours_securite=# \dt production.*
              List of relations
   Schema   |     Name     | Type  |  Owner   
------------+--------------+-------+----------
 production | clients      | table | philippe
 production | transactions | table | philippe
(2 rows)

cours_securite=# \dt research.*
              List of relations
  Schema  |     Name      | Type  |  Owner   
----------+---------------+-------+----------
 research | algos_trading | table | philippe
(1 row)


Son rôle dans l'ensemble du projet est donc de préparer les données sources. Il intervient en amont du chiffrement.

### `encryption_utils.py`

Ce fichier est le coeur technique du projet. Il centralise toute la logique de chiffrement et évite de dupliquer le code entre scripts et interface.

Il contient principalement :
- la découverte des fichiers `.dump` via `list_dump_files()` ;
- la logique de dérivation de clé à partir d'une phrase de passe ;
- les fonctions de chiffrement symétrique `DES`, `Triple DES`, `AES` et `Twofish` ;
- les fonctions de chiffrement asymétrique `RSA`, `ECC` et `ICP` ;
- la construction du fichier de sortie chiffré avec des métadonnées embarquées.

En pratique, ce module prend un fichier source, applique l'algorithme choisi, puis écrit un fichier `.enc` dans le même dossier que l'original.

### `streamlit_app.py`

Ce fichier constitue l'interface utilisateur du projet.

Son rôle est d'orchestrer l'utilisation des algorithmes de chiffrement :
- il affiche les dossiers disponibles ;
- il permet de choisir un dossier, puis un fichier `.dump` ;
- il propose un onglet pour le chiffrement symétrique ;
- il propose un onglet pour le chiffrement asymétrique ;
- il transmet les paramètres choisis aux fonctions définies dans `encryption_utils.py`.

L'application le pilotage des différents moteurs de chiffrement.

### `environment.yml`

Ce fichier décrit l'environnement conda du projet.

Il permet de recréer un environnement cohérent avec :
- Python ;
- Jupyter ;
- Streamlit ;
- les bibliothèques cryptographiques nécessaires.

Il sert surtout à rendre le projet réexécutable sur une autre machine ou dans une autre session.

### `requirements.txt`

Ce fichier fournit une alternative légère à conda pour installer les dépendances avec `pip`.

Il complète `environment.yml` et permet une installation plus directe si l'on ne souhaite pas reconstruire tout l'environnement conda.

### `.gitignore`

Le `.gitignore` protège le dépôt contre l'ajout de fichiers générés ou locaux, notamment :
- les dumps PostgreSQL ;
- les fichiers chiffrés `.enc` ;
- les exports CSV ;
- les caches Python et fichiers temporaires.

Il permet de versionner le code et la documentation sans pousser les artefacts lourds ou sensibles.

### `backups/`

Ce dossier contient les dumps PostgreSQL générés depuis le notebook ou les tests.

Dans le flux du projet, c'est le dossier d'entrée principal pour l'interface de chiffrement. Les fichiers chiffrés y sont également écrits par défaut, à côté du fichier source sélectionné.

### `csv_exports/`

Ce dossier contient les exports tabulaires au format CSV.

Il montre la partie extraction et valorisation des données. Même si l'application Streamlit cible surtout les fichiers `.dump`, ces exports illustrent le lien entre sécurité, sauvegarde et exploitation de la donnée.

## Articulation entre les fichiers

Le flux logique du projet peut se lire de cette manière :

1. `chiffrement_donnees.ipynb` produit les sauvegardes et exports.
2. Les dumps générés sont stockés dans `backups/`.
3. `streamlit_app.py` affiche ces fichiers dans son interface.
4. Lorsqu'un utilisateur choisit un algorithme, `streamlit_app.py` appelle les fonctions de `encryption_utils.py`.
5. `encryption_utils.py` chiffre le fichier et génère un nouveau fichier `.enc` dans le même répertoire.

Cette séparation a un intérêt pédagogique important :
- le notebook montre la préparation des données ;
- le module Python montre la logique cryptographique ;
- l'interface montre comment transformer cette logique en outil simple à manipuler.

## Exemple de scénario complet

1. Exporter une base PostgreSQL avec le notebook.
2. Vérifier que le dump apparaît dans `backups/`.
3. Lancer l'interface Streamlit.
4. Choisir le dossier contenant les dumps.
5. Sélectionner un fichier d'entrée.
6. Choisir un algorithme de chiffrement.
7. Générer le fichier chiffré dans le même répertoire.

Ce scénario montre comment les différentes briques du dépôt s'enchaînent de manière cohérente.

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

## Lancer le projet

### Ouvrir le notebook

```bash
jupyter lab
```

### Lancer l'interface Streamlit

```bash
streamlit run streamlit_app.py
```

## Dépendances principales

Le projet s'appuie notamment sur :
- `cryptography`
- `pycryptodome`
- `twofish`
- `streamlit`
- `pandas`
- `jupyterlab`

## Compatibilité Python et bibliothèques

Le projet a été préparé pour fonctionner avec une version récente de Python, en particulier Python `3.13`.

Ce point mérite d'être signalé car toutes les bibliothèques de chiffrement ne sont pas toujours immédiatement compatibles avec les versions les plus récentes du langage.

### Problème rencontré

Lors de l'implémentation de l'algorithme `Twofish`, un problème de compatibilité est apparu avec la bibliothèque `twofish`.

Le paquet installé contenait bien son extension compilée, mais son module Python principal utilisait `imp`, un ancien module de la bibliothèque standard supprimé dans les versions modernes de Python.

En pratique :
- l'import classique du paquet `twofish` échouait sous Python `3.13` ;
- l'algorithme ne pouvait donc pas être utilisé directement via son interface Python standard ;
- le coeur compilé de la bibliothèque restait pourtant présent et exploitable.

### Solution mise en place

Pour conserver `Twofish` dans le projet sans revenir à une version plus ancienne de Python, une adaptation a été faite dans [encryption_utils.py](./encryption_utils.py) :
- le projet n'utilise pas le wrapper Python cassé fourni par le paquet ;
- il charge directement le module binaire `_twofish` ;
- les fonctions natives sont appelées avec `ctypes` ;
- la localisation du module compilé est résolue avec `importlib.util.find_spec`.

Cette solution permet :
- de garder Python `3.13` comme base de travail ;
- de conserver l'algorithme `Twofish` dans l'application ;
- d'éviter qu'une dépendance partiellement obsolète bloque tout le projet.

### Ce que cela montre

Ce cas illustre une idée importante dans un projet de sécurité :
- un algorithme peut rester pertinent sur le plan théorique ;
- mais son implémentation logicielle peut devenir fragile si la bibliothèque n'est plus maintenue au même rythme que Python.

Autrement dit, la robustesse d'un projet dépend non seulement des algorithmes choisis, mais aussi de la compatibilité réelle des bibliothèques qui les implémentent.

## Points pédagogiques importants

- `DES` et `Triple DES` sont présents pour l'apprentissage, même s'ils ne sont plus recommandés comme standards modernes.
- `AES` reste la référence symétrique la plus robuste du projet.
- `RSA`, `ECC` et l'approche par certificat permettent d'introduire la logique de chiffrement asymétrique.
- le projet montre aussi qu'une interface simple peut rendre des opérations techniques plus accessibles.

## Limites assumées

- ce projet est avant tout un support d'apprentissage ;
- il ne remplace pas une architecture de sécurité complète ;
- la gestion des secrets, du déchiffrement, de la rotation des clés et de l'audit avancé pourrait être approfondie dans une suite du projet.

## Bonus

Le bonus du projet réside dans l'interface Streamlit, qui transforme un exercice technique en mini-outil interactif de démonstration.

Elle permet de passer d'une logique purement scriptée à une approche plus visuelle, plus lisible et plus facile à présenter dans un contexte de soutenance ou de démonstration.

## Auteur

Projet réalisé dans le cadre d'un travail d'école sur la sécurité des données, l'utilisation de PostgreSQL et l'apprentissage des standards de chiffrement en Python.
