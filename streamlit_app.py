from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from encryption_utils import (
    charger_historique_transactions,
    charger_materiel_cryptographique,
    chiffrer_fichier_asymetrique,
    chiffrer_fichier_symetrique,
    dechiffrer_fichier_asymetrique,
    dechiffrer_fichier_symetrique,
    generer_certificat_autosigne,
    generer_paire_cles_ecc,
    generer_paire_cles_rsa,
    inspecter_fichier_chiffre,
    lister_fichiers_chiffrables,
    lister_fichiers_chiffres,
    lister_jeux_cles,
    supprimer_jeu_cles,
)

PROJECT_DIR = Path(__file__).resolve().parent
BACKUP_DIR = PROJECT_DIR / "backups"

SYMMETRIC_ALGORITHMS = ["DES", "Triple DES", "AES", "Twofish"]
ASYMMETRIC_ALGORITHMS = ["RSA", "ECC", "Infrastructure a cle publique (ICP)"]
KEY_GENERATION_OPTIONS = [
    "Paire de clés RSA",
    "Paire de clés ECC",
    "Certificat ICP RSA",
    "Certificat ICP ECC",
]


def _apply_app_theme() -> None:
    st.markdown(
        """
        <style>
        :root {
            --cs-bg: #f8f8fc;
            --cs-sidebar: #f3f4fb;
            --cs-card: #ffffff;
            --cs-card-strong: #ffffff;
            --cs-border: rgba(165, 174, 204, 0.18);
            --cs-text: #2f3443;
            --cs-muted: #7a8196;
            --cs-accent: #7f7de8;
            --cs-accent-soft: #eeedff;
            --cs-secondary: #76b7b2;
            --cs-secondary-soft: #ebfbf8;
            --cs-warm: #f2b8d5;
            --cs-success-soft: #e9f8ef;
            --cs-info-soft: #edf2ff;
            --cs-pending-soft: #f4f1ff;
        }

        .stApp {
            background: var(--cs-bg);
            color: var(--cs-text);
        }

        [data-testid="stAppViewContainer"] > .main {
            background: transparent;
        }

        [data-testid="stSidebar"] {
            background: var(--cs-sidebar);
            border-right: 1px solid var(--cs-border);
        }

        h1, h2, h3 {
            color: var(--cs-text);
            letter-spacing: -0.02em;
        }

        strong {
            color: var(--cs-text);
        }

        p, li, label, .stCaption {
            color: var(--cs-muted);
        }

        [data-testid="stVerticalBlockBorderWrapper"] {
            background: var(--cs-card);
            border: 1px solid var(--cs-border);
            border-radius: 22px;
            box-shadow: 0 8px 24px rgba(99, 105, 140, 0.05);
        }

        [data-testid="stTabs"] [data-baseweb="tab-list"] {
            gap: 0.75rem;
            background: transparent;
            border-bottom: 1px solid rgba(122, 129, 150, 0.10);
            padding-bottom: 0.45rem;
        }

        [data-testid="stTabs"] [data-baseweb="tab"] {
            height: 44px;
            border-radius: 999px;
            padding: 0 1rem;
            color: var(--cs-muted);
            background: rgba(255,255,255,0.65);
            border: 1px solid rgba(165, 174, 204, 0.14);
        }

        [data-testid="stTabs"] [aria-selected="true"] {
            background: var(--cs-accent-soft);
            color: var(--cs-accent);
            font-weight: 700;
            border: 1px solid rgba(127, 125, 232, 0.20);
        }

        .stButton > button, .stDownloadButton > button {
            border-radius: 16px;
            border: 1px solid rgba(165, 174, 204, 0.16);
            background: #ffffff;
            color: var(--cs-text);
            font-weight: 700;
            min-height: 3rem;
            box-shadow: 0 4px 12px rgba(99, 105, 140, 0.04);
        }

        .stButton > button:hover, .stDownloadButton > button:hover {
            border-color: rgba(127, 125, 232, 0.22);
            color: var(--cs-accent);
            background: #fafaff;
        }

        [data-testid="stMetric"] {
            background: #f8fbff;
            border: 1px solid rgba(165, 174, 204, 0.14);
            border-radius: 20px;
            padding: 0.75rem 1rem;
        }

        [data-testid="stInfo"], [data-testid="stSuccess"], [data-testid="stWarning"], [data-testid="stError"] {
            border-radius: 18px;
            border-width: 1px;
        }

        [data-testid="stSelectbox"], [data-testid="stTextInput"], [data-testid="stFileUploader"], [data-testid="stNumberInput"] {
            background: transparent;
        }

        [data-baseweb="select"] > div, .stTextInput input, .stNumberInput input {
            border-radius: 16px !important;
            background: #ffffff !important;
            border: 1px solid rgba(165, 174, 204, 0.14) !important;
        }

        [data-testid="stDataFrame"] {
            background: #ffffff;
            border-radius: 20px;
            padding: 0.35rem;
            border: 1px solid var(--cs-border);
        }

        .cs-step-title {
            color: var(--cs-text);
            font-weight: 700;
            font-size: 1rem;
            margin: 0.2rem 0 0.15rem 0;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

def _render_step_inline(step_number: int, title: str, action: str, effect: str) -> None:
    st.markdown(f"<div class='cs-step-title'>Étape {step_number} - {title}</div>", unsafe_allow_html=True)
    st.caption(f"Que faire : {action}")
    st.caption(f"Ce que cela fera : {effect}")


def _render_sidebar_step_one(has_source_files: bool, has_encrypted_files: bool) -> None:
    st.markdown("### Étape 1")
    st.markdown("**Choisir un fichier**")
    st.caption("Que faire : sélectionner dans cette barre latérale un fichier source à chiffrer ou un `.enc` à déchiffrer.")
    st.caption("Ce que cela fera : l'application saura quel contenu afficher et quelle suite d'étapes proposer.")

    if not has_source_files:
        st.info("Aucun fichier source à chiffrer dans ce dossier pour le moment.")
    if not has_encrypted_files:
        st.info("Aucun fichier `.enc` dans ce dossier pour le moment.")


def _format_size(size_in_bytes: int) -> str:
    units = ["octets", "Ko", "Mo", "Go"]
    size = float(size_in_bytes)
    unit = units[0]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024
    return f"{size:.2f} {unit}"


def _list_available_directories(root_dir: Path) -> list[Path]:
    directories = [root_dir]
    for path in sorted(root_dir.rglob("*")):
        if not path.is_dir():
            continue
        if path.name.startswith(".") or path.name == "__pycache__":
            continue
        directories.append(path)
    return directories


def _format_duration(duration_ms: float) -> str:
    if duration_ms < 1000:
        return f"{duration_ms:.3f} ms"
    return f"{duration_ms / 1000:.3f} s"


def _format_timestamp(iso_value: str) -> str:
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError:
        return iso_value

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone().strftime("%d/%m/%Y %H:%M:%S %Z")


def _format_operation(operation: str) -> str:
    return "Chiffrement" if operation == "encryption" else "Déchiffrement"


def _render_history() -> None:
    st.subheader("Historique des transactions")
    entries = charger_historique_transactions(limit=50)

    if not entries:
        st.info("Aucune transaction enregistrée pour le moment.")
        return

    rows = [
        {
            "Date": _format_timestamp(entry.get("created_at_utc", "")),
            "Opération": _format_operation(str(entry.get("operation", "encryption"))),
            "Type": "Symétrique" if entry.get("family") == "symmetric" else "Asymétrique",
            "Algorithme": entry.get("algorithm", "-"),
            "Fichier source": entry.get("source_name", "-"),
            "Sortie": entry.get("output_name", "-"),
            "Taille source": _format_size(int(entry.get("source_size_bytes", 0))),
            "Temps d'exécution": _format_duration(float(entry.get("execution_time_ms", 0.0))),
        }
        for entry in entries
    ]

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _render_selected_file(source_path: Path) -> None:
    st.subheader("Fichier sélectionné")
    st.write(f"Nom : `{source_path.name}`")
    st.write(f"Dossier : `{source_path.parent}`")
    st.write(f"Taille : `{_format_size(source_path.stat().st_size)}`")


def _bundle_summary(bundle: dict[str, object]) -> str:
    label = str(bundle.get("label", "Sans nom"))
    kind = "Certificat" if bundle.get("kind") == "certificate" else "Paire de clés"
    algorithm = str(bundle.get("algorithm", "-"))
    return f"{label} - {algorithm} ({kind})"


def _get_compatible_bundles(algorithm: str) -> list[dict[str, object]]:
    bundles = lister_jeux_cles()
    if algorithm == "Infrastructure a cle publique (ICP)":
        return [bundle for bundle in bundles if bundle.get("kind") == "certificate"]

    return [
        bundle
        for bundle in bundles
        if bundle.get("kind") == "key_pair" and str(bundle.get("algorithm", "")).upper() == algorithm.upper()
    ]


def _get_bundle_material_path(bundle: dict[str, object], algorithm: str) -> str:
    files = bundle.get("files", {})
    if not isinstance(files, dict):
        raise ValueError("Bundle de clés invalide.")

    key_name = "certificate" if algorithm == "Infrastructure a cle publique (ICP)" else "public_key"
    material_path = files.get(key_name)
    if not isinstance(material_path, str):
        raise ValueError("Matériel cryptographique introuvable dans le bundle sélectionné.")
    return material_path


def _get_private_key_path(bundle: dict[str, object]) -> str:
    files = bundle.get("files", {})
    if not isinstance(files, dict):
        raise ValueError("Bundle de clés invalide.")

    private_key_path = files.get("private_key")
    if not isinstance(private_key_path, str):
        raise ValueError("Clé privée introuvable dans le bundle sélectionné.")
    return private_key_path


def _render_bundle_downloads(bundle: dict[str, object]) -> None:
    files = bundle.get("files", {})
    if not isinstance(files, dict):
        st.error("Impossible de lire les fichiers de ce bundle.")
        return

    download_specs = [
        ("public_key", "Télécharger la clé publique"),
        ("private_key", "Télécharger la clé privée"),
        ("certificate", "Télécharger le certificat"),
    ]

    for file_key, label in download_specs:
        file_path = files.get(file_key)
        if not isinstance(file_path, str):
            continue

        path_obj = Path(file_path)
        try:
            file_data = charger_materiel_cryptographique(path_obj)
        except Exception as exc:
            st.warning(f"Lecture impossible pour `{path_obj.name}` : {exc}")
            continue

        st.download_button(
            label=label,
            data=file_data,
            file_name=path_obj.name,
            mime="application/x-pem-file",
            use_container_width=True,
            key=f"download_{bundle.get('id', 'bundle')}_{file_key}",
        )


def _render_bundle_summary_card(bundle: dict[str, object]) -> None:
    label = str(bundle.get("label", "Sans nom"))
    algorithm = str(bundle.get("algorithm", "-"))
    kind = "Certificat" if bundle.get("kind") == "certificate" else "Paire de clés"
    created_at = _format_timestamp(str(bundle.get("created_at_utc", "")))

    details = bundle.get("details", {})
    if not isinstance(details, dict):
        details = {}

    files = bundle.get("files", {})
    if not isinstance(files, dict):
        files = {}

    badge_col, info_col = st.columns([0.9, 1.4])
    with badge_col:
        st.markdown(f"**Type**  \n`{kind}`")
        st.markdown(f"**Algo**  \n`{algorithm}`")
    with info_col:
        st.markdown(f"**Nom**  \n`{label}`")
        st.markdown(f"**Créé le**  \n`{created_at}`")

    detail_parts = []
    if "key_size" in details:
        detail_parts.append(f"Taille RSA : `{details['key_size']} bits`")
    if "curve" in details:
        detail_parts.append(f"Courbe : `{details['curve']}`")
    if "common_name" in details:
        detail_parts.append(f"CN : `{details['common_name']}`")
    if "validity_days" in details:
        detail_parts.append(f"Validité : `{details['validity_days']} jours`")

    if detail_parts:
        st.caption(" | ".join(detail_parts))

    file_lines = []
    if "public_key" in files:
        file_lines.append(f"Clé publique : `{Path(str(files['public_key'])).name}`")
    if "private_key" in files:
        file_lines.append(f"Clé privée : `{Path(str(files['private_key'])).name}`")
    if "certificate" in files:
        file_lines.append(f"Certificat : `{Path(str(files['certificate'])).name}`")

    if file_lines:
        st.markdown("\n".join(file_lines))


def _get_compatible_private_bundles(inspection: dict[str, object]) -> list[dict[str, object]]:
    metadata = inspection.get("metadata", {})
    if not isinstance(metadata, dict):
        return []

    if str(metadata.get("family", "")).lower() != "asymmetric":
        return []

    target_algorithm = "ECC" if "ephemeral_public_key_pem" in metadata else "RSA"
    bundles = lister_jeux_cles()
    return [bundle for bundle in bundles if str(bundle.get("algorithm", "")).upper() == target_algorithm]


def _render_key_management() -> None:
    with st.expander("Gestion des clés et certificats", expanded=False):
        bundles = lister_jeux_cles()
        _render_step_inline(
            3,
            "Préparer une clé ou un certificat",
            "si tu n'as pas encore de matériel cryptographique, génère ici un jeu de clés ou un certificat adapté.",
            "l'application créera les fichiers nécessaires pour chiffrer puis, plus tard, déchiffrer.",
        )
        left_col, right_col = st.columns([1.3, 1])

        with left_col:
            generation_type = st.selectbox("Type à générer", KEY_GENERATION_OPTIONS, key="key_generation_type")
            label = st.text_input("Nom du jeu de clés", value="demo", key="key_bundle_label")

            rsa_key_size = 2048
            ecc_curve = "SECP256R1"
            common_name = "cours-securite.local"
            validity_days = 365

            if generation_type == "Paire de clés RSA":
                rsa_key_size = st.selectbox("Taille RSA", [2048, 3072, 4096], index=0, key="rsa_key_size")
            elif generation_type == "Paire de clés ECC":
                ecc_curve = st.selectbox(
                    "Courbe ECC",
                    ["SECP256R1", "SECP384R1", "SECP521R1"],
                    index=0,
                    key="ecc_curve",
                )
            else:
                common_name = st.text_input("Common Name (CN)", value="cours-securite.local", key="cert_common_name")
                validity_days = st.number_input("Validité (jours)", min_value=1, value=365, step=1, key="cert_days")

            if st.button("Générer", use_container_width=True, key="generate_key_bundle"):
                if not label.strip():
                    st.error("Renseigne un nom pour le jeu de clés.")
                else:
                    try:
                        if generation_type == "Paire de clés RSA":
                            bundle = generer_paire_cles_rsa(label.strip(), rsa_key_size)
                        elif generation_type == "Paire de clés ECC":
                            bundle = generer_paire_cles_ecc(label.strip(), ecc_curve)
                        elif generation_type == "Certificat ICP RSA":
                            bundle = generer_certificat_autosigne(label.strip(), "RSA", common_name.strip(), int(validity_days))
                        else:
                            bundle = generer_certificat_autosigne(label.strip(), "ECC", common_name.strip(), int(validity_days))
                    except Exception as exc:
                        st.error(f"Génération impossible : {exc}")
                    else:
                        st.success(f"Jeu créé : {bundle['label']}")
                        st.rerun()

        with right_col:
            st.write(f"Jeux disponibles : `{len(bundles)}`")
            if not bundles:
                st.info("Aucune clé locale pour le moment.")
            else:
                selected_bundle = st.selectbox(
                    "Bibliothèque locale",
                    bundles,
                    format_func=_bundle_summary,
                    key="managed_bundle_overview",
                )
                _render_bundle_summary_card(selected_bundle)
                _render_bundle_downloads(selected_bundle)
                if st.button("Supprimer ce jeu", type="secondary", use_container_width=True, key="delete_key_bundle"):
                    try:
                        supprimer_jeu_cles(str(selected_bundle["id"]))
                    except Exception as exc:
                        st.error(f"Suppression impossible : {exc}")
                    else:
                        st.success("Jeu de clés supprimé.")
                        st.rerun()


def _symmetric_tab(source_path: Path | None) -> None:
    st.subheader("Chiffrement symétrique")
    if source_path is None:
        st.warning("Aucun fichier source disponible dans ce dossier pour le chiffrement.")
        return

    st.markdown("Le chiffrement symétrique utilise un même secret pour chiffrer et déchiffrer.")
    st.caption("Ici, ce secret est ta phrase de passe. Il faudra donc la conserver pour pouvoir rouvrir le fichier plus tard.")
    _render_selected_file(source_path)
    _render_step_inline(
        2,
        "Choisir l’algorithme",
        "sélectionner l'algorithme symétrique à utiliser.",
        "l'application appliquera cette méthode pour produire un fichier `.enc`.",
    )
    algorithm = st.selectbox("Algorithme symétrique", SYMMETRIC_ALGORITHMS, key="symmetric_algorithm")
    _render_step_inline(
        3,
        "Saisir la phrase de passe",
        "entrer puis confirmer la phrase de passe.",
        "cette phrase servira à dériver la clé nécessaire au chiffrement puis au futur déchiffrement.",
    )
    passphrase = st.text_input("Phrase de passe", type="password", key="symmetric_passphrase")
    confirm_passphrase = st.text_input("Confirmation", type="password", key="symmetric_confirm")

    if algorithm in {"DES", "Triple DES"}:
        st.warning("DES et Triple DES sont conservés ici pour le projet, mais ils sont considérés comme faibles face aux standards actuels.")

    _render_step_inline(
        4,
        "Lancer le chiffrement",
        "cliquer sur le bouton de chiffrement.",
        "un fichier chiffré sera créé dans le même dossier, avec son temps d'exécution et ses métadonnées.",
    )
    if st.button("Chiffrer en symétrique", use_container_width=True):
        if not passphrase:
            st.error("Renseigne une phrase de passe.")
            return
        if passphrase != confirm_passphrase:
            st.error("Les deux phrases de passe ne correspondent pas.")
            return

        try:
            result = chiffrer_fichier_symetrique(source_path, algorithm, passphrase)
        except Exception as exc:
            st.error(f"Erreur pendant le chiffrement : {exc}")
            return

        st.success(f"Fichier chiffré créé : {result.output_path.name}")
        st.metric("Temps d'exécution", _format_duration(result.execution_time_ms))
        st.code(str(result.output_path))
        st.json(result.metadata)


def _asymmetric_tab(source_path: Path | None) -> None:
    st.subheader("Chiffrement asymétrique")
    if source_path is None:
        st.warning("Aucun fichier source disponible dans ce dossier pour le chiffrement.")
        return

    st.markdown("Le chiffrement asymétrique repose sur une paire de clés : une clé publique pour chiffrer et une clé privée pour déchiffrer.")
    st.caption("Ici, tu fournis une clé publique ou un certificat. La clé privée correspondante sera nécessaire plus tard pour rouvrir le fichier.")
    _render_selected_file(source_path)
    _render_step_inline(
        2,
        "Choisir l’algorithme asymétrique",
        "sélectionner RSA, ECC ou ICP.",
        "l'application saura quel type de clé publique ou de certificat utiliser.",
    )
    algorithm = st.selectbox(
        "Algorithme asymétrique",
        ASYMMETRIC_ALGORITHMS,
        key="asymmetric_algorithm",
        format_func=lambda value: "Infrastructure à clé publique (ICP)" if value == "Infrastructure a cle publique (ICP)" else value,
    )
    _render_key_management()

    if algorithm == "Infrastructure a cle publique (ICP)":
        helper = "Charge un certificat X.509 PEM/DER (.pem, .crt, .cer)."
        accepted_types = ["pem", "crt", "cer", "der"]
    else:
        helper = "Charge une clé publique PEM compatible avec l'algorithme choisi."
        accepted_types = ["pem"]

    st.caption(helper)
    key_source = st.radio(
        "Source du matériel cryptographique",
        ["Bibliothèque locale", "Upload manuel"],
        horizontal=True,
        key="asymmetric_key_source",
    )
    _render_step_inline(
        3,
        "Fournir une clé publique ou un certificat",
        "utiliser la bibliothèque locale ou charger un fichier compatible.",
        "le fichier sera chiffré pour la personne qui possède la clé privée correspondante.",
    )

    key_material: bytes | None = None
    compatible_bundles = _get_compatible_bundles(algorithm)

    if key_source == "Bibliothèque locale":
        if not compatible_bundles:
            st.warning("Aucun élément compatible dans la bibliothèque locale. Génère une clé ou passe en upload manuel.")
        else:
            selected_bundle = st.selectbox(
                "Clé publique ou certificat disponible",
                compatible_bundles,
                format_func=_bundle_summary,
                key="asymmetric_managed_material",
            )
            try:
                material_path = _get_bundle_material_path(selected_bundle, algorithm)
                key_material = charger_materiel_cryptographique(material_path)
            except Exception as exc:
                st.error(f"Impossible de charger le matériel sélectionné : {exc}")
            else:
                st.caption(f"Fichier utilisé : `{Path(material_path).name}`")
    else:
        uploaded_key = st.file_uploader(
            "Clé publique ou certificat",
            type=accepted_types,
            key="asymmetric_key_material",
        )
        if uploaded_key is not None:
            key_material = uploaded_key.getvalue()

    st.info("Le fichier chiffré sera écrit dans le même répertoire que le fichier source. La clé privée correspondante sera nécessaire pour le déchiffrement.")

    _render_step_inline(
        4,
        "Lancer le chiffrement",
        "cliquer sur le bouton de chiffrement et conserver la clé privée associée.",
        "un fichier `.enc` sera créé et ne pourra être ouvert qu'avec la bonne clé privée.",
    )
    if st.button("Chiffrer en asymétrique", use_container_width=True):
        if key_material is None:
            st.error("Charge d'abord une clé publique ou un certificat.")
            return

        try:
            result = chiffrer_fichier_asymetrique(source_path, algorithm, key_material)
        except Exception as exc:
            st.error(f"Erreur pendant le chiffrement : {exc}")
            return

        st.success(f"Fichier chiffré créé : {result.output_path.name}")
        st.metric("Temps d'exécution", _format_duration(result.execution_time_ms))
        st.code(str(result.output_path))
        st.json(result.metadata)


def _decryption_tab(source_path: Path | None) -> None:
    st.subheader("Déchiffrement")
    if source_path is None:
        st.warning("Aucun fichier `.enc` disponible dans ce dossier pour le déchiffrement.")
        return

    st.markdown("Le déchiffrement consiste à revenir au fichier d'origine à partir du fichier protégé.")
    st.caption("Selon la méthode utilisée au départ, tu devras fournir soit la phrase de passe d'origine, soit la clé privée correspondante.")
    _render_selected_file(source_path)

    try:
        inspection = inspecter_fichier_chiffre(source_path)
    except Exception as exc:
        st.error(f"Impossible d'inspecter le fichier chiffré : {exc}")
        return

    metadata = inspection.get("metadata", {})
    if not isinstance(metadata, dict):
        st.error("Les métadonnées du fichier chiffré sont invalides.")
        return

    st.caption(
        f"Type : `{inspection.get('family', '-')}` | "
        f"Algorithme : `{inspection.get('algorithm', '-')}` | "
        f"Fichier source attendu : `{inspection.get('source_name', '-')}`"
    )
    _render_step_inline(
        2,
        "Identifier le type de fichier",
        "lire la famille et l'algorithme détectés.",
        "tu sauras si tu dois fournir une phrase de passe ou une clé privée.",
    )

    family = str(metadata.get("family", "")).lower()

    if family == "symmetric":
        _render_step_inline(
            3,
            "Fournir la phrase de passe",
            "saisir la phrase de passe utilisée au moment du chiffrement.",
            "l'application pourra reconstruire la clé nécessaire au déchiffrement.",
        )
        passphrase = st.text_input("Phrase de passe de déchiffrement", type="password", key="decrypt_passphrase")
        _render_step_inline(
            4,
            "Lancer le déchiffrement",
            "cliquer sur `Déchiffrer`.",
            "le fichier d'origine sera recréé dans le même dossier si la phrase de passe est correcte.",
        )
        if st.button("Déchiffrer", use_container_width=True, key="decrypt_symmetric_button"):
            if not passphrase:
                st.error("Renseigne la phrase de passe de déchiffrement.")
                return
            try:
                result = dechiffrer_fichier_symetrique(source_path, passphrase)
            except Exception as exc:
                st.error(f"Erreur pendant le déchiffrement : {exc}")
                return

            st.success(f"Fichier déchiffré créé : {result.output_path.name}")
            st.metric("Temps d'exécution", _format_duration(result.execution_time_ms))
            st.code(str(result.output_path))
            st.json(result.metadata)
        return

    if family == "asymmetric":
        key_source = st.radio(
            "Source de la clé privée",
            ["Bibliothèque locale", "Upload manuel"],
            horizontal=True,
            key="decryption_key_source",
        )
        _render_step_inline(
            3,
            "Fournir la clé privée",
            "charger la clé privée correspondant au fichier chiffré.",
            "l'application récupérera la clé de session puis le contenu original du fichier.",
        )

        private_key_data: bytes | None = None
        compatible_bundles = _get_compatible_private_bundles(inspection)

        if key_source == "Bibliothèque locale":
            if not compatible_bundles:
                st.warning("Aucune clé privée compatible dans la bibliothèque locale.")
            else:
                selected_bundle = st.selectbox(
                    "Clé privée disponible",
                    compatible_bundles,
                    format_func=_bundle_summary,
                    key="decryption_private_bundle",
                )
                try:
                    private_key_path = _get_private_key_path(selected_bundle)
                    private_key_data = charger_materiel_cryptographique(private_key_path)
                except Exception as exc:
                    st.error(f"Impossible de charger la clé privée sélectionnée : {exc}")
                else:
                    st.caption(f"Clé privée utilisée : `{Path(private_key_path).name}`")
        else:
            uploaded_private_key = st.file_uploader(
                "Clé privée PEM",
                type=["pem"],
                key="decryption_private_key_upload",
            )
            if uploaded_private_key is not None:
                private_key_data = uploaded_private_key.getvalue()

        _render_step_inline(
            4,
            "Lancer le déchiffrement",
            "cliquer sur `Déchiffrer` quand la clé privée est prête.",
            "le fichier source sera régénéré si la clé privée correspond bien au chiffrement utilisé.",
        )

        if st.button("Déchiffrer", use_container_width=True, key="decrypt_asymmetric_button"):
            if private_key_data is None:
                st.error("Charge d'abord une clé privée compatible.")
                return
            try:
                result = dechiffrer_fichier_asymetrique(source_path, private_key_data)
            except Exception as exc:
                st.error(f"Erreur pendant le déchiffrement : {exc}")
                return

            st.success(f"Fichier déchiffré créé : {result.output_path.name}")
            st.metric("Temps d'exécution", _format_duration(result.execution_time_ms))
            st.code(str(result.output_path))
            st.json(result.metadata)
        return

    st.error("Famille de chiffrement non supportée pour le déchiffrement.")


def main() -> None:
    st.set_page_config(page_title="Chiffrement des dumps", layout="wide")
    _apply_app_theme()
    st.title("Chiffrement des dumps PostgreSQL")
    st.write("Cette interface sert de support d'apprentissage : elle t'accompagne pour chiffrer, déchiffrer et comprendre ce que fait chaque étape.")

    available_directories = _list_available_directories(PROJECT_DIR)
    selected_dump_path = None
    selected_encrypted_path = None
    has_compatible_files = False
    selected_directory = PROJECT_DIR
    with st.sidebar:
        st.header("Sélection")
        if st.button("Rafraîchir la liste", use_container_width=True):
            st.rerun()

        default_dir_index = available_directories.index(BACKUP_DIR) if BACKUP_DIR in available_directories else 0
        selected_directory = st.selectbox(
            "Dossier d'entrée",
            available_directories,
            index=default_dir_index,
            format_func=lambda path: str(path.relative_to(PROJECT_DIR)) if path != PROJECT_DIR else ".",
        )

        source_files = lister_fichiers_chiffrables(selected_directory)
        encrypted_files = lister_fichiers_chiffres(selected_directory)
        has_compatible_files = bool(source_files or encrypted_files)
        _render_sidebar_step_one(bool(source_files), bool(encrypted_files))

        if not has_compatible_files:
            relative_directory = str(selected_directory.relative_to(PROJECT_DIR)) if selected_directory != PROJECT_DIR else "."
            st.warning(f"Aucun fichier source ni fichier `.enc` dans `{relative_directory}`.")

        if source_files:
            selected_dump_path = st.selectbox(
                "Fichier source à chiffrer",
                source_files,
                format_func=lambda path: f"{path.name} ({_format_size(path.stat().st_size)})",
            )
        else:
            st.caption("Aucun fichier source à chiffrer dans ce dossier.")

        if encrypted_files:
            selected_encrypted_path = st.selectbox(
                "Fichier chiffré pour déchiffrement",
                encrypted_files,
                format_func=lambda path: f"{path.name} ({_format_size(path.stat().st_size)})",
            )
        else:
            st.caption("Aucun fichier `.enc` dans ce dossier.")

    if not has_compatible_files:
        relative_directory = str(selected_directory.relative_to(PROJECT_DIR)) if selected_directory != PROJECT_DIR else "."
        st.info(
            f"Aucun fichier compatible n'est disponible dans `{relative_directory}`. "
            "Choisis un autre dossier dans la barre latérale pour continuer."
        )
        st.caption("Formats attendus : n'importe quel fichier source pour le chiffrement et `.enc` pour le déchiffrement.")
        st.divider()
        _render_history()
        return

    symmetric_tab, asymmetric_tab, decryption_tab = st.tabs(["Symétrique", "Asymétrique", "Déchiffrement"])
    with symmetric_tab:
        _symmetric_tab(selected_dump_path)
    with asymmetric_tab:
        _asymmetric_tab(selected_dump_path)
    with decryption_tab:
        _decryption_tab(selected_encrypted_path)

    st.divider()
    _render_history()


if __name__ == "__main__":
    main()
