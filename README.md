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

## Problématique

Le besoin de départ est le suivant : une entreprise manipulant des données sensibles doit pouvoir protéger ses sauvegardes de base de données et ses fichiers de travail avant stockage ou partage.

Dans ce projet, cette problématique a été traduite de façon concrète autour de trois usages :
- produire une sauvegarde PostgreSQL de la base `cours_securite` ;
- exporter des données tabulaires en `csv` et manipuler d'autres formats de travail comme `txt` ou `xlsx` ;
- tester plusieurs méthodes de chiffrement depuis une interface Streamlit afin de comparer leur comportement sur les mêmes fichiers.

La question centrale n'est donc pas seulement "comment chiffrer un fichier ?", mais plutôt :
- quelle famille de chiffrement est la plus adaptée à des sauvegardes de base de données et à des fichiers métiers ;
- quels algorithmes restent pertinents aujourd'hui ;
- quelle solution faut-il retenir en pratique après comparaison.

## Démarche de sélection de la méthode

La méthode suivie dans le projet repose sur un enchaînement simple :

1. Préparer des données réalistes avec le notebook : dump PostgreSQL, exports CSV, fichiers de travail.
2. Utiliser Streamlit pour appliquer plusieurs algorithmes sur un même type de fichier.
3. Mesurer et observer les résultats via le temps d'exécution, le succès du déchiffrement et l'historique local.
4. Comparer les familles de chiffrement selon quatre critères :
   - niveau de sécurité ;
   - performance ;
   - simplicité d'usage ;
   - adéquation avec le chiffrement de fichiers complets.
5. Retenir une méthode finale adaptée au besoin réel, et non seulement une méthode "qui fonctionne".

Cette démarche permet de distinguer :
- les algorithmes présents pour l'apprentissage et la comparaison ;
- l'algorithme réellement recommandé pour le cas d'usage visé.

## Réponse concrète retenue

L'application permet de tester plusieurs approches :
- en symétrique : `DES`, `Triple DES`, `AES`, `Twofish` ;
- en asymétrique : `RSA`, `ECC`, `ICP`.

Cependant, pour le besoin principal du projet, la réponse concrète retenue est la suivante :

- le chiffrement des sauvegardes de base de données et des fichiers métiers repose prioritairement sur `AES` ;
- les méthodes `RSA`, `ECC` et `ICP` sont conservées pour l'étude comparative, la compréhension du chiffrement asymétrique et les scénarios de protection de clé ;
- `DES` et `Triple DES` sont présents à titre pédagogique, mais ne constituent pas un choix recommandé ;
- `Twofish` reste intéressant pour la comparaison, mais `AES` est la solution la plus cohérente ici en termes de robustesse, de compatibilité et de simplicité d'exploitation.

En pratique, la réponse opérationnelle du projet peut se résumer ainsi :

`base PostgreSQL ou fichier de travail -> export/sauvegarde -> chiffrement AES -> stockage du fichier .enc -> déchiffrement contrôlé si besoin`

Autrement dit, Streamlit sert ici de laboratoire de test pour comparer toutes les méthodes, mais la conclusion concrète du projet est qu'un chiffrement symétrique `AES` est le meilleur choix pour protéger les fichiers eux-mêmes.

## Tests réalisés pour choisir la méthode de chiffrement

Le choix de la méthode ne repose pas uniquement sur la réussite du chiffrement. Le projet s'appuie sur une logique de test comparative appliquée aux mêmes fichiers sources.

### Jeu de données de test

Les essais peuvent être menés sur plusieurs types de fichiers produits ou manipulés dans le projet :
- sauvegardes PostgreSQL au format `dump` ;
- exports tabulaires au format `csv` ;
- fichiers texte `txt` ;
- fichiers bureautiques `xlsx`.

L'intérêt de ce jeu de données est de confronter les algorithmes à des contenus variés :
- données structurées ;
- fichiers de tailles différentes ;
- fichiers métiers proches d'un usage réel.

### Protocole de test

Pour chaque algorithme, le même pipeline est appliqué :

1. sélectionner un fichier source depuis l'interface Streamlit ;
2. chiffrer ce fichier avec un algorithme donné ;
3. mesurer le temps d'exécution enregistré par l'application ;
4. déchiffrer le fichier obtenu ;
5. vérifier que le contenu restauré reste exploitable et cohérent avec le fichier d'origine ;
6. consulter l'historique local pour comparer les opérations.

Cette logique permet d'évaluer chaque méthode dans les mêmes conditions d'usage.

### Critères d'évaluation

Le choix final s'appuie sur quatre critères principaux :

- `Sécurité` : résistance générale de l'algorithme et pertinence vis-à-vis des standards actuels ;
- `Performance` : rapidité du chiffrement et du déchiffrement sur des fichiers complets ;
- `Simplicité d'exploitation` : facilité de mise en oeuvre, gestion des secrets et risque d'erreur utilisateur ;
- `Adéquation au besoin` : pertinence pour protéger directement des sauvegardes et des fichiers métiers.

### Lecture des résultats

Les tests comparatifs conduisent à distinguer deux usages :

- les algorithmes symétriques sont les plus adaptés au chiffrement direct de fichiers complets ;
- les algorithmes asymétriques sont surtout pertinents pour la gestion de clés, les certificats et les scénarios d'échange sécurisé.

Dans le détail :

- `DES` et `Triple DES` permettent d'illustrer l'évolution historique des méthodes, mais ils ne constituent plus un choix satisfaisant pour un besoin moderne ;
- `RSA`, `ECC` et `ICP` sont très utiles pour comprendre le chiffrement asymétrique, mais ils ne sont pas la réponse la plus simple ni la plus efficace pour chiffrer directement des sauvegardes volumineuses ;
- `Twofish` offre une comparaison intéressante, mais reste moins standard dans ce projet ;
- `AES` fournit le meilleur compromis entre sécurité, vitesse, compatibilité et lisibilité pédagogique.

## Justification finale du choix d'AES

Le choix final d'`AES` est retenu pour plusieurs raisons complémentaires :

- c'est l'algorithme symétrique le plus cohérent pour chiffrer directement des fichiers de sauvegarde et des exports ;
- il offre un très bon niveau de sécurité dans un cadre moderne ;
- il reste plus simple à exploiter qu'une solution asymétrique pour des fichiers complets ;
- il s'intègre naturellement dans le pipeline mis en place dans le projet ;
- il permet de formuler une réponse claire au besoin métier sans complexifier inutilement l'usage.

La conclusion du projet peut donc être formulée ainsi :

`tester plusieurs méthodes pour comprendre -> comparer leurs comportements sur les mêmes fichiers -> retenir AES comme solution concrète de chiffrement des données`

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
- comparer concrètement plusieurs méthodes de chiffrement sur une même base de test ;
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
