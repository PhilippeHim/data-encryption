from __future__ import annotations

from pathlib import Path

import streamlit as st

from encryption_utils import encrypt_asymmetric_file, encrypt_symmetric_file, list_dump_files

PROJECT_DIR = Path(__file__).resolve().parent
BACKUP_DIR = PROJECT_DIR / "backups"

SYMMETRIC_ALGORITHMS = ["DES", "Triple DES", "AES", "Twofish"]
ASYMMETRIC_ALGORITHMS = ["RSA", "ECC", "Infrastructure a cle publique (ICP)"]


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


def _render_selected_file(source_path: Path) -> None:
    st.subheader("Fichier selectionne")
    st.write(f"Nom : `{source_path.name}`")
    st.write(f"Dossier : `{source_path.parent}`")
    st.write(f"Taille : `{_format_size(source_path.stat().st_size)}`")


def _symmetric_tab(source_path: Path) -> None:
    st.subheader("Chiffrement symetrique")
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
        st.code(str(result.output_path))
        st.json(result.metadata)


def _asymmetric_tab(source_path: Path) -> None:
    st.subheader("Chiffrement asymetrique")
    algorithm = st.selectbox("Algorithme asymetrique", ASYMMETRIC_ALGORITHMS, key="asymmetric_algorithm")

    if algorithm == "Infrastructure a cle publique (ICP)":
        helper = "Charge un certificat X.509 PEM/DER (.pem, .crt, .cer)."
        accepted_types = ["pem", "crt", "cer", "der"]
    else:
        helper = "Charge une cle publique PEM compatible avec l'algorithme choisi."
        accepted_types = ["pem"]

    st.caption(helper)
    uploaded_key = st.file_uploader(
        "Cle publique ou certificat",
        type=accepted_types,
        key="asymmetric_key_material",
    )
    st.info("Le fichier chiffre sera ecrit dans le meme repertoire que le dump source. La cle privee correspondante sera necessaire pour le dechiffrement.")

    if st.button("Chiffrer en asymetrique", use_container_width=True):
        if uploaded_key is None:
            st.error("Charge d'abord une cle publique ou un certificat.")
            return

        try:
            result = encrypt_asymmetric_file(source_path, algorithm, uploaded_key.getvalue())
        except Exception as exc:
            st.error(f"Erreur pendant le chiffrement : {exc}")
            return

        st.success(f"Fichier chiffre cree : {result.output_path.name}")
        st.code(str(result.output_path))
        st.json(result.metadata)


def main() -> None:
    st.set_page_config(page_title="Chiffrement des dumps", layout="wide")
    st.title("Chiffrement des dumps PostgreSQL")
    st.write("Cette interface permet de chiffrer les dumps du dossier `backups` un par un, avec un fichier de sortie cree dans le meme repertoire.")

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

        if not dump_files:
            st.warning(f"Aucun fichier `.dump` n'a ete trouve dans le dossier `{selected_directory}`.")
            return

        selected_path = st.selectbox(
            "Fichier d'entree",
            dump_files,
            format_func=lambda path: f"{path.name} ({_format_size(path.stat().st_size)})",
        )

    _render_selected_file(selected_path)

    symmetric_tab, asymmetric_tab = st.tabs(["Symetrique", "Asymetrique"])
    with symmetric_tab:
        _symmetric_tab(selected_path)
    with asymmetric_tab:
        _asymmetric_tab(selected_path)


if __name__ == "__main__":
    main()
