from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from encryption_utils import (
    delete_managed_key_bundle,
    decrypt_asymmetric_file,
    decrypt_symmetric_file,
    encrypt_asymmetric_file,
    encrypt_symmetric_file,
    generate_ecc_key_pair,
    generate_rsa_key_pair,
    generate_self_signed_certificate,
    list_dump_files,
    list_encrypted_files,
    list_managed_key_bundles,
    load_transaction_history,
    load_key_material,
    inspect_encrypted_file,
)

PROJECT_DIR = Path(__file__).resolve().parent
BACKUP_DIR = PROJECT_DIR / "backups"

SYMMETRIC_ALGORITHMS = ["DES", "Triple DES", "AES", "Twofish"]
ASYMMETRIC_ALGORITHMS = ["RSA", "ECC", "Infrastructure a cle publique (ICP)"]
KEY_GENERATION_OPTIONS = [
    "Paire de cles RSA",
    "Paire de cles ECC",
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

        .cs-hero {
            background: #f7f5ff;
            border: 1px solid var(--cs-border);
            border-radius: 28px;
            padding: 1.35rem 1.5rem;
            margin: 0.4rem 0 1.1rem 0;
            box-shadow: 0 10px 28px rgba(99, 105, 140, 0.05);
        }

        .cs-hero-title {
            font-size: 1.08rem;
            font-weight: 700;
            color: var(--cs-text);
            margin-bottom: 0.35rem;
        }

        .cs-hero-text {
            color: var(--cs-muted);
            margin: 0;
            line-height: 1.55;
        }

        .cs-step-chip {
            display: inline-block;
            margin-top: 0.4rem;
            padding: 0.5rem 0.8rem;
            border-radius: 999px;
            font-size: 0.95rem;
            font-weight: 600;
        }

        .cs-step-chip.done {
            background: var(--cs-success-soft);
            color: #4d8a67;
        }

        .cs-step-chip.current {
            background: var(--cs-info-soft);
            color: #5f73c8;
        }

        .cs-step-chip.pending {
            background: var(--cs-pending-soft);
            color: #8d86b8;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _step_state_label(step_index: int, current_step: int) -> str:
    if step_index < current_step:
        return "Terminee"
    if step_index == current_step:
        return "En cours"
    return "A venir"


def _step_state_class(step_index: int, current_step: int) -> str:
    if step_index < current_step:
        return "done"
    if step_index == current_step:
        return "current"
    return "pending"


def _render_tp_stepper(title: str, steps: list[dict[str, str]], current_step: int) -> None:
    st.markdown(f"#### {title}")
    columns = st.columns(len(steps))
    for index, (column, step) in enumerate(zip(columns, steps), start=1):
        with column:
            with st.container(border=True):
                st.markdown(f"**Etape {index}**")
                st.write(step["title"])
                st.caption(f"Que faire : {step['action']}")
                st.caption(f"Ce que cela fera : {step['effect']}")
                state = _step_state_label(index, current_step)
                state_class = _step_state_class(index, current_step)
                st.markdown(
                    f'<span class="cs-step-chip {state_class}">{state}</span>',
                    unsafe_allow_html=True,
                )


def _render_learning_header() -> None:
    st.markdown("### Parcours guide")
    _render_tp_stepper(
        "Vue d'ensemble du TP",
        [
            {
                "title": "Choisir un dossier et un fichier",
                "action": "Utiliser la barre laterale pour selectionner un `.dump` ou un `.enc`.",
                "effect": "L'application saura quel fichier afficher et quel type d'action rendre possible.",
            },
            {
                "title": "Choisir l'onglet adapte",
                "action": "Ouvrir `Symetrique`, `Asymetrique` ou `Dechiffrement` selon ton besoin.",
                "effect": "Tu verras uniquement les champs utiles a l'etape choisie.",
            },
            {
                "title": "Fournir les informations demandees",
                "action": "Renseigner phrase de passe, cle publique, certificat ou cle privee selon le cas.",
                "effect": "L'application preparera correctement le chiffrement ou le dechiffrement.",
            },
            {
                "title": "Lancer puis analyser le resultat",
                "action": "Cliquer sur l'action principale et lire le resultat affiche.",
                "effect": "Tu recupereras le fichier produit, son temps d'execution et ses metadonnees.",
            },
        ],
        2,
    )


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
    return "Chiffrement" if operation == "encryption" else "Dechiffrement"


def _render_history() -> None:
    st.subheader("Historique des transactions")
    entries = load_transaction_history(limit=50)

    if not entries:
        st.info("Aucune transaction enregistree pour le moment.")
        return

    rows = [
        {
            "Date": _format_timestamp(entry.get("created_at_utc", "")),
            "Operation": _format_operation(str(entry.get("operation", "encryption"))),
            "Type": "Symetrique" if entry.get("family") == "symmetric" else "Asymetrique",
            "Algorithme": entry.get("algorithm", "-"),
            "Fichier source": entry.get("source_name", "-"),
            "Sortie": entry.get("output_name", "-"),
            "Taille source": _format_size(int(entry.get("source_size_bytes", 0))),
            "Temps d'execution": _format_duration(float(entry.get("execution_time_ms", 0.0))),
        }
        for entry in entries
    ]

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _render_selected_file(source_path: Path) -> None:
    st.subheader("Fichier selectionné")
    st.write(f"Nom : `{source_path.name}`")
    st.write(f"Dossier : `{source_path.parent}`")
    st.write(f"Taille : `{_format_size(source_path.stat().st_size)}`")


def _bundle_summary(bundle: dict[str, object]) -> str:
    label = str(bundle.get("label", "Sans nom"))
    kind = "Certificat" if bundle.get("kind") == "certificate" else "Paire de cles"
    algorithm = str(bundle.get("algorithm", "-"))
    return f"{label} - {algorithm} ({kind})"


def _get_compatible_bundles(algorithm: str) -> list[dict[str, object]]:
    bundles = list_managed_key_bundles()
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
        raise ValueError("Bundle de cles invalide.")

    key_name = "certificate" if algorithm == "Infrastructure a cle publique (ICP)" else "public_key"
    material_path = files.get(key_name)
    if not isinstance(material_path, str):
        raise ValueError("Materiel cryptographique introuvable dans le bundle selectionne.")
    return material_path


def _get_private_key_path(bundle: dict[str, object]) -> str:
    files = bundle.get("files", {})
    if not isinstance(files, dict):
        raise ValueError("Bundle de cles invalide.")

    private_key_path = files.get("private_key")
    if not isinstance(private_key_path, str):
        raise ValueError("Cle privee introuvable dans le bundle selectionne.")
    return private_key_path


def _render_bundle_downloads(bundle: dict[str, object]) -> None:
    files = bundle.get("files", {})
    if not isinstance(files, dict):
        st.error("Impossible de lire les fichiers de ce bundle.")
        return

    download_specs = [
        ("public_key", "Telecharger la cle publique"),
        ("private_key", "Telecharger la cle privee"),
        ("certificate", "Telecharger le certificat"),
    ]

    for file_key, label in download_specs:
        file_path = files.get(file_key)
        if not isinstance(file_path, str):
            continue

        path_obj = Path(file_path)
        try:
            file_data = load_key_material(path_obj)
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
    kind = "Certificat" if bundle.get("kind") == "certificate" else "Paire de cles"
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
        st.markdown(f"**Cree le**  \n`{created_at}`")

    detail_parts = []
    if "key_size" in details:
        detail_parts.append(f"Taille RSA : `{details['key_size']} bits`")
    if "curve" in details:
        detail_parts.append(f"Courbe : `{details['curve']}`")
    if "common_name" in details:
        detail_parts.append(f"CN : `{details['common_name']}`")
    if "validity_days" in details:
        detail_parts.append(f"Validite : `{details['validity_days']} jours`")

    if detail_parts:
        st.caption(" | ".join(detail_parts))

    file_lines = []
    if "public_key" in files:
        file_lines.append(f"Cle publique : `{Path(str(files['public_key'])).name}`")
    if "private_key" in files:
        file_lines.append(f"Cle privee : `{Path(str(files['private_key'])).name}`")
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
    bundles = list_managed_key_bundles()
    return [bundle for bundle in bundles if str(bundle.get("algorithm", "")).upper() == target_algorithm]


def _render_key_management() -> None:
    with st.expander("Gestion des cles et certificats", expanded=False):
        bundles = list_managed_key_bundles()
        current_step = 2 if bundles else 1
        _render_tp_stepper(
            "Etapes de la gestion des cles",
            [
                {
                    "title": "Generer un jeu de cles ou un certificat",
                    "action": "Choisir un type de generation puis remplir les champs affiches.",
                    "effect": "L'application creera localement les fichiers cryptographiques necessaires.",
                },
                {
                    "title": "Relire le contenu du bundle",
                    "action": "Verifier l'algorithme, le type et les fichiers generes dans la bibliotheque locale.",
                    "effect": "Tu confirmes que tu utilises bien le bon materiel pour la suite.",
                },
                {
                    "title": "Telecharger ou reutiliser les fichiers utiles",
                    "action": "Recuperer les fichiers ou les selectionner plus bas dans l'onglet asymetrique.",
                    "effect": "La cle publique ou le certificat pourra servir au chiffrement, et la cle privee au dechiffrement.",
                },
            ],
            current_step,
        )
        left_col, right_col = st.columns([1.3, 1])

        with left_col:
            generation_type = st.selectbox("Type a generer", KEY_GENERATION_OPTIONS, key="key_generation_type")
            label = st.text_input("Nom du jeu de cles", value="demo", key="key_bundle_label")

            rsa_key_size = 2048
            ecc_curve = "SECP256R1"
            common_name = "cours-securite.local"
            validity_days = 365

            if generation_type == "Paire de cles RSA":
                rsa_key_size = st.selectbox("Taille RSA", [2048, 3072, 4096], index=0, key="rsa_key_size")
            elif generation_type == "Paire de cles ECC":
                ecc_curve = st.selectbox(
                    "Courbe ECC",
                    ["SECP256R1", "SECP384R1", "SECP521R1"],
                    index=0,
                    key="ecc_curve",
                )
            else:
                common_name = st.text_input("Common Name (CN)", value="cours-securite.local", key="cert_common_name")
                validity_days = st.number_input("Validite (jours)", min_value=1, value=365, step=1, key="cert_days")

            if st.button("Generer", use_container_width=True, key="generate_key_bundle"):
                if not label.strip():
                    st.error("Renseigne un nom pour le jeu de cles.")
                else:
                    try:
                        if generation_type == "Paire de cles RSA":
                            bundle = generate_rsa_key_pair(label.strip(), rsa_key_size)
                        elif generation_type == "Paire de cles ECC":
                            bundle = generate_ecc_key_pair(label.strip(), ecc_curve)
                        elif generation_type == "Certificat ICP RSA":
                            bundle = generate_self_signed_certificate(label.strip(), "RSA", common_name.strip(), int(validity_days))
                        else:
                            bundle = generate_self_signed_certificate(label.strip(), "ECC", common_name.strip(), int(validity_days))
                    except Exception as exc:
                        st.error(f"Generation impossible : {exc}")
                    else:
                        st.success(f"Jeu cree : {bundle['label']}")
                        st.rerun()

        with right_col:
            st.write(f"Jeux disponibles : `{len(bundles)}`")
            if not bundles:
                st.info("Aucune cle locale pour le moment.")
            else:
                selected_bundle = st.selectbox(
                    "Bibliotheque locale",
                    bundles,
                    format_func=_bundle_summary,
                    key="managed_bundle_overview",
                )
                _render_bundle_summary_card(selected_bundle)
                _render_bundle_downloads(selected_bundle)
                if st.button("Supprimer ce jeu", type="secondary", use_container_width=True, key="delete_key_bundle"):
                    try:
                        delete_managed_key_bundle(str(selected_bundle["id"]))
                    except Exception as exc:
                        st.error(f"Suppression impossible : {exc}")
                    else:
                        st.success("Jeu de cles supprime.")
                        st.rerun()


def _symmetric_tab(source_path: Path | None) -> None:
    st.subheader("Chiffrement symetrique")
    if source_path is None:
        st.warning("Aucun fichier `.dump` disponible dans ce dossier pour le chiffrement.")
        return

    current_step = 2
    if st.session_state.get("symmetric_passphrase"):
        current_step = 3
    if st.session_state.get("symmetric_passphrase") and st.session_state.get("symmetric_confirm"):
        current_step = 4

    _render_tp_stepper(
        "Etapes du TP symetrique",
        [
            {
                "title": "Choisir le dump a traiter",
                "action": "Verifier dans la barre laterale que le bon fichier `.dump` est selectionne.",
                "effect": "C'est ce fichier qui sera chiffre dans le meme dossier.",
            },
            {
                "title": "Choisir l'algorithme",
                "action": "Selectionner DES, Triple DES, AES ou Twofish.",
                "effect": "L'application appliquera la methode choisie pour produire le fichier `.enc`.",
            },
            {
                "title": "Saisir la phrase de passe",
                "action": "Entrer puis confirmer la phrase de passe.",
                "effect": "Cette phrase servira a deriver la cle necessaire au chiffrement puis au futur dechiffrement.",
            },
            {
                "title": "Lancer et lire le resultat",
                "action": "Cliquer sur le bouton de chiffrement.",
                "effect": "Tu obtiendras un fichier chiffre, son temps d'execution et ses metadonnees.",
            },
        ],
        current_step,
    )
    _render_selected_file(source_path)
    algorithm = st.selectbox("Algorithme symetrique", SYMMETRIC_ALGORITHMS, key="symmetric_algorithm")
    passphrase = st.text_input("Phrase de passe", type="password", key="symmetric_passphrase")
    confirm_passphrase = st.text_input("Confirmation", type="password", key="symmetric_confirm")

    if algorithm in {"DES", "Triple DES"}:
        st.warning("DES et Triple DES sont conserves ici pour le projet, mais ils sont consideres comme faibles face aux standards actuels.")

    if st.button("Chiffrer en symetrique", use_container_width=True):
        if not passphrase:
            st.error("Renseigne une phrase de passe.")
            return
        if passphrase != confirm_passphrase:
            st.error("Les deux phrases de passe ne correspondent pas.")
            return

        try:
            result = encrypt_symmetric_file(source_path, algorithm, passphrase)
        except Exception as exc:
            st.error(f"Erreur pendant le chiffrement : {exc}")
            return

        st.success(f"Fichier chiffre cree : {result.output_path.name}")
        st.metric("Temps d'execution", _format_duration(result.execution_time_ms))
        st.code(str(result.output_path))
        st.json(result.metadata)


def _asymmetric_tab(source_path: Path | None) -> None:
    st.subheader("Chiffrement asymetrique")
    if source_path is None:
        st.warning("Aucun fichier `.dump` disponible dans ce dossier pour le chiffrement.")
        return

    _render_tp_stepper(
        "Etapes du TP asymetrique",
        [
            {
                "title": "Choisir le dump a traiter",
                "action": "Verifier le fichier `.dump` selectionne dans la barre laterale.",
                "effect": "C'est ce fichier qui sera protege avec le mecanisme asymetrique.",
            },
            {
                "title": "Choisir l'algorithme asymetrique",
                "action": "Selectionner RSA, ECC ou ICP.",
                "effect": "L'application saura quel type de cle publique ou de certificat attendre.",
            },
            {
                "title": "Preparer une cle publique ou un certificat",
                "action": "Utiliser la bibliotheque locale ou un upload manuel.",
                "effect": "Le fichier sera chiffre pour le destinataire possedant la cle privee correspondante.",
            },
            {
                "title": "Lancer et garder la cle privee pour la suite",
                "action": "Cliquer sur le bouton de chiffrement et conserver la cle privee associee.",
                "effect": "Tu produiras un `.enc` qui ne pourra etre ouvert qu'avec la bonne cle privee.",
            },
        ],
        2,
    )
    _render_selected_file(source_path)
    algorithm = st.selectbox("Algorithme asymetrique", ASYMMETRIC_ALGORITHMS, key="asymmetric_algorithm")
    _render_key_management()

    if algorithm == "Infrastructure a cle publique (ICP)":
        helper = "Charge un certificat X.509 PEM/DER (.pem, .crt, .cer)."
        accepted_types = ["pem", "crt", "cer", "der"]
    else:
        helper = "Charge une cle publique PEM compatible avec l'algorithme choisi."
        accepted_types = ["pem"]

    st.caption(helper)
    key_source = st.radio(
        "Source du materiel cryptographique",
        ["Bibliotheque locale", "Upload manuel"],
        horizontal=True,
        key="asymmetric_key_source",
    )

    key_material: bytes | None = None
    compatible_bundles = _get_compatible_bundles(algorithm)

    if key_source == "Bibliotheque locale":
        if not compatible_bundles:
            st.warning("Aucun element compatible dans la bibliotheque locale. Genere une cle ou passe en upload manuel.")
        else:
            selected_bundle = st.selectbox(
                "Cle publique ou certificat disponible",
                compatible_bundles,
                format_func=_bundle_summary,
                key="asymmetric_managed_material",
            )
            try:
                material_path = _get_bundle_material_path(selected_bundle, algorithm)
                key_material = load_key_material(material_path)
            except Exception as exc:
                st.error(f"Impossible de charger le materiel selectionne : {exc}")
            else:
                st.caption(f"Fichier utilise : `{Path(material_path).name}`")
    else:
        uploaded_key = st.file_uploader(
            "Cle publique ou certificat",
            type=accepted_types,
            key="asymmetric_key_material",
        )
        if uploaded_key is not None:
            key_material = uploaded_key.getvalue()

    if key_material is not None:
        _render_tp_stepper(
            "Progression actuelle",
            [
                {"title": "Dump choisi", "action": "Ne rien changer si le bon fichier est deja selectionne.", "effect": "Le bon fichier restera la source du traitement."},
                {"title": "Algorithme defini", "action": "Verifier que l'algorithme correspond bien au type de cle disponible.", "effect": "Tu eviteras un mismatch entre algorithme et materiel cryptographique."},
                {"title": "Materiel cryptographique pret", "action": "Confirmer que la cle publique ou le certificat est bien charge.", "effect": "Le chiffrement pourra se lancer correctement."},
                {"title": "Action finale : chiffrer", "action": "Cliquer sur le bouton principal.", "effect": "Le fichier `.enc` sera cree dans le meme dossier."},
            ],
            4,
        )
    else:
        _render_tp_stepper(
            "Progression actuelle",
            [
                {"title": "Dump choisi", "action": "Verifier le fichier selectionne.", "effect": "Tu chiffres bien le bon contenu."},
                {"title": "Algorithme defini", "action": "Choisir RSA, ECC ou ICP.", "effect": "L'application sait quel type de materiel te demander."},
                {"title": "Materiel cryptographique a fournir", "action": "Charger une cle publique ou un certificat.", "effect": "Le chiffrement deviendra possible."},
                {"title": "Action finale : chiffrer", "action": "Cliquer quand le materiel est pret.", "effect": "Le fichier chiffre sera genere."},
            ],
            3,
        )

    st.info("Le fichier chiffre sera ecrit dans le meme repertoire que le dump source. La cle privee correspondante sera necessaire pour le dechiffrement.")

    if st.button("Chiffrer en asymetrique", use_container_width=True):
        if key_material is None:
            st.error("Charge d'abord une cle publique ou un certificat.")
            return

        try:
            result = encrypt_asymmetric_file(source_path, algorithm, key_material)
        except Exception as exc:
            st.error(f"Erreur pendant le chiffrement : {exc}")
            return

        st.success(f"Fichier chiffre cree : {result.output_path.name}")
        st.metric("Temps d'execution", _format_duration(result.execution_time_ms))
        st.code(str(result.output_path))
        st.json(result.metadata)


def _decryption_tab(source_path: Path | None) -> None:
    st.subheader("Dechiffrement")
    if source_path is None:
        st.warning("Aucun fichier `.enc` disponible dans ce dossier pour le dechiffrement.")
        return

    _render_tp_stepper(
        "Etapes du TP de dechiffrement",
        [
            {
                "title": "Choisir un fichier chiffre",
                "action": "Selectionner un fichier `.enc` dans la barre laterale.",
                "effect": "L'application analysera ses metadonnees pour savoir comment le traiter.",
            },
            {
                "title": "Identifier son type",
                "action": "Lire la famille et l'algorithme detectes juste en dessous.",
                "effect": "Tu sauras si tu dois fournir une phrase de passe ou une cle privee.",
            },
            {
                "title": "Fournir le bon secret",
                "action": "Donner la phrase de passe ou la cle privee correspondante.",
                "effect": "L'application pourra retrouver le contenu original du fichier.",
            },
            {
                "title": "Lancer puis comparer au fichier d'origine",
                "action": "Cliquer sur `Dechiffrer` puis observer le fichier produit.",
                "effect": "Tu verifies que la methode choisie permet bien de revenir au document source.",
            },
        ],
        2,
    )
    _render_selected_file(source_path)

    try:
        inspection = inspect_encrypted_file(source_path)
    except Exception as exc:
        st.error(f"Impossible d'inspecter le fichier chiffre : {exc}")
        return

    metadata = inspection.get("metadata", {})
    if not isinstance(metadata, dict):
        st.error("Les metadonnees du fichier chiffre sont invalides.")
        return

    st.caption(
        f"Type : `{inspection.get('family', '-')}` | "
        f"Algorithme : `{inspection.get('algorithm', '-')}` | "
        f"Fichier source attendu : `{inspection.get('source_name', '-')}`"
    )

    family = str(metadata.get("family", "")).lower()

    if family == "symmetric":
        current_step = 3 if st.session_state.get("decrypt_passphrase") else 2
        _render_tp_stepper(
            "Progression actuelle",
            [
                {"title": "Fichier `.enc` choisi", "action": "Verifier le bon fichier chiffre.", "effect": "Tu travailles sur le bon document."},
                {"title": "Type symetrique detecte", "action": "Lire l'algorithme detecte.", "effect": "Tu sais qu'une phrase de passe sera necessaire."},
                {"title": "Phrase de passe a fournir", "action": "Saisir la phrase de passe d'origine.", "effect": "L'application pourra reconstruire la cle de dechiffrement."},
                {"title": "Action finale : dechiffrer", "action": "Cliquer sur le bouton principal.", "effect": "Le fichier original sera recree dans le meme dossier."},
            ],
            current_step + 1 if st.session_state.get("decrypt_passphrase") else current_step,
        )
        passphrase = st.text_input("Phrase de passe de dechiffrement", type="password", key="decrypt_passphrase")
        if st.button("Dechiffrer", use_container_width=True, key="decrypt_symmetric_button"):
            if not passphrase:
                st.error("Renseigne la phrase de passe de dechiffrement.")
                return
            try:
                result = decrypt_symmetric_file(source_path, passphrase)
            except Exception as exc:
                st.error(f"Erreur pendant le dechiffrement : {exc}")
                return

            st.success(f"Fichier dechiffre cree : {result.output_path.name}")
            st.metric("Temps d'execution", _format_duration(result.execution_time_ms))
            st.code(str(result.output_path))
            st.json(result.metadata)
        return

    if family == "asymmetric":
        key_source = st.radio(
            "Source de la cle privee",
            ["Bibliotheque locale", "Upload manuel"],
            horizontal=True,
            key="decryption_key_source",
        )

        private_key_data: bytes | None = None
        compatible_bundles = _get_compatible_private_bundles(inspection)

        if key_source == "Bibliotheque locale":
            if not compatible_bundles:
                st.warning("Aucune cle privee compatible dans la bibliotheque locale.")
            else:
                selected_bundle = st.selectbox(
                    "Cle privee disponible",
                    compatible_bundles,
                    format_func=_bundle_summary,
                    key="decryption_private_bundle",
                )
                try:
                    private_key_path = _get_private_key_path(selected_bundle)
                    private_key_data = load_key_material(private_key_path)
                except Exception as exc:
                    st.error(f"Impossible de charger la cle privee selectionnee : {exc}")
                else:
                    st.caption(f"Cle privee utilisee : `{Path(private_key_path).name}`")
        else:
            uploaded_private_key = st.file_uploader(
                "Cle privee PEM",
                type=["pem"],
                key="decryption_private_key_upload",
            )
            if uploaded_private_key is not None:
                private_key_data = uploaded_private_key.getvalue()

        _render_tp_stepper(
            "Progression actuelle",
            [
                {"title": "Fichier `.enc` choisi", "action": "Verifier le fichier selectionne.", "effect": "Le bon document sera dechiffre."},
                {"title": "Type asymetrique detecte", "action": "Observer s'il s'agit d'un flux RSA ou ECC.", "effect": "Tu sauras quelle cle privee fournir."},
                {"title": "Cle privee a fournir", "action": "Charger la cle privee compatible.", "effect": "L'application pourra recuperer la cle de session puis le contenu original."},
                {"title": "Action finale : dechiffrer", "action": "Cliquer sur `Dechiffrer`.", "effect": "Le fichier source sera regenere."},
            ],
            4 if private_key_data is not None else 3,
        )

        if st.button("Dechiffrer", use_container_width=True, key="decrypt_asymmetric_button"):
            if private_key_data is None:
                st.error("Charge d'abord une cle privee compatible.")
                return
            try:
                result = decrypt_asymmetric_file(source_path, private_key_data)
            except Exception as exc:
                st.error(f"Erreur pendant le dechiffrement : {exc}")
                return

            st.success(f"Fichier dechiffre cree : {result.output_path.name}")
            st.metric("Temps d'execution", _format_duration(result.execution_time_ms))
            st.code(str(result.output_path))
            st.json(result.metadata)
        return

    st.error("Famille de chiffrement non supportee pour le dechiffrement.")


def main() -> None:
    st.set_page_config(page_title="Chiffrement des dumps", layout="wide")
    _apply_app_theme()
    st.title("Chiffrement des dumps PostgreSQL")
    st.write("Cette interface sert de support d'apprentissage : elle t'accompagne pour chiffrer, dechiffrer et comprendre ce que fait chaque etape.")
    _render_learning_header()

    available_directories = _list_available_directories(PROJECT_DIR)
    with st.sidebar:
        st.header("Selection")
        if st.button("Rafraichir la liste", use_container_width=True):
            st.rerun()

        default_dir_index = available_directories.index(BACKUP_DIR) if BACKUP_DIR in available_directories else 0
        selected_directory = st.selectbox(
            "Dossier d'entree",
            available_directories,
            index=default_dir_index,
            format_func=lambda path: str(path.relative_to(PROJECT_DIR)) if path != PROJECT_DIR else ".",
        )

        dump_files = list_dump_files(selected_directory)
        encrypted_files = list_encrypted_files(selected_directory)

        if not dump_files and not encrypted_files:
            st.warning(f"Aucun fichier `.dump` ou `.enc` n'a ete trouve dans le dossier `{selected_directory}`.")
            return

        selected_dump_path = None
        if dump_files:
            selected_dump_path = st.selectbox(
                "Fichier source pour chiffrement",
                dump_files,
                format_func=lambda path: f"{path.name} ({_format_size(path.stat().st_size)})",
            )
        else:
            st.caption("Aucun fichier `.dump` dans ce dossier.")

        selected_encrypted_path = None
        if encrypted_files:
            selected_encrypted_path = st.selectbox(
                "Fichier chiffre pour dechiffrement",
                encrypted_files,
                format_func=lambda path: f"{path.name} ({_format_size(path.stat().st_size)})",
            )
        else:
            st.caption("Aucun fichier `.enc` dans ce dossier.")

    symmetric_tab, asymmetric_tab, decryption_tab = st.tabs(["Symetrique", "Asymetrique", "Dechiffrement"])
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
