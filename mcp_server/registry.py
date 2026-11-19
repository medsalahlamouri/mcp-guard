"""Mémoire à long terme de MCP-Guard (SQLite).

Partagée entre le serveur MCP (tools approuver / vérifier) et le backend web
(historique, tableau de bord, réaudit planifié).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "mcp_guard.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS serveurs_approuves (
    nom TEXT PRIMARY KEY,
    chemin TEXT NOT NULL,
    empreinte TEXT NOT NULL,
    date_approbation TEXT NOT NULL,
    statut TEXT NOT NULL DEFAULT 'approuvé',
    derniere_verification TEXT
);
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    cible TEXT NOT NULL,
    type TEXT,
    score INTEGER,
    verdict TEXT,
    rapport TEXT,
    donnees TEXT,
    session_id TEXT,
    cout_usd REAL
);
CREATE TABLE IF NOT EXISTS alertes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    cible TEXT NOT NULL,
    type TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    evenement TEXT NOT NULL,
    details TEXT
);
CREATE TABLE IF NOT EXISTS sources (
    chemin TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    url TEXT,
    commit_sha TEXT,
    date TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS preferences (
    cle TEXT PRIMARY KEY,
    valeur TEXT NOT NULL,
    date TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    titre TEXT NOT NULL,
    audit_id INTEGER,
    creee TEXT NOT NULL,
    mise_a_jour TEXT NOT NULL,
    messages INTEGER NOT NULL DEFAULT 1
);
"""

# Préférences utilisateur (mémoire à long terme) et leurs valeurs autorisées.
PREFERENCES_DEFAUT = {"niveau_detail": "standard", "email_notification": ""}
NIVEAUX_DETAIL = ("synthétique", "standard", "détaillé")

# Colonnes ajoutées après la première version : migration douce (les audits existants sont conservés).
MIGRATIONS = {
    "audits": {"drive_lien": "TEXT", "drive_statut": "TEXT", "email_statut": "TEXT"},
}


def maintenant() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def connexion() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    for table, colonnes in MIGRATIONS.items():
        existantes = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
        for nom, type_ in colonnes.items():
            if nom not in existantes:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {nom} {type_}")
    return con


def journaliser(evenement: str, details: dict | str = "") -> None:
    """Journal d'audit (OWASP MCP08 : traçabilité des actions)."""
    with connexion() as con:
        con.execute("INSERT INTO journal (date, evenement, details) VALUES (?,?,?)",
                    (maintenant(), evenement, json.dumps(details, ensure_ascii=False)
                     if not isinstance(details, str) else details))


def approuver(nom: str, chemin: str, empreinte: dict) -> None:
    with connexion() as con:
        con.execute(
            "INSERT OR REPLACE INTO serveurs_approuves (nom, chemin, empreinte, date_approbation, statut, derniere_verification) "
            "VALUES (?,?,?,?, 'approuvé', ?)",
            (nom, chemin, json.dumps(empreinte), maintenant(), maintenant()))
    journaliser("approbation", {"nom": nom, "chemin": chemin})


def obtenir_approuve(nom: str) -> dict | None:
    with connexion() as con:
        ligne = con.execute("SELECT * FROM serveurs_approuves WHERE nom = ?", (nom,)).fetchone()
    if not ligne:
        return None
    d = dict(ligne)
    d["empreinte"] = json.loads(d["empreinte"])
    return d


def lister_approuves() -> list[dict]:
    with connexion() as con:
        lignes = con.execute("SELECT nom, chemin, date_approbation, statut, derniere_verification "
                             "FROM serveurs_approuves ORDER BY date_approbation DESC").fetchall()
    return [dict(l) for l in lignes]


def changer_statut(nom: str, statut: str) -> None:
    with connexion() as con:
        con.execute("UPDATE serveurs_approuves SET statut = ?, derniere_verification = ? WHERE nom = ?",
                    (statut, maintenant(), nom))


def enregistrer_audit(cible, type_, score, verdict, rapport, donnees, session_id=None, cout=None) -> int:
    with connexion() as con:
        cur = con.execute(
            "INSERT INTO audits (date, cible, type, score, verdict, rapport, donnees, session_id, cout_usd) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (maintenant(), cible, type_, score, verdict, rapport, json.dumps(donnees, ensure_ascii=False),
             session_id, cout))
        return cur.lastrowid


def lister_audits(limite: int = 50) -> list[dict]:
    with connexion() as con:
        lignes = con.execute("SELECT id, date, cible, type, score, verdict, cout_usd, drive_lien, drive_statut, "
                             "email_statut FROM audits ORDER BY id DESC LIMIT ?", (limite,)).fetchall()
    return [dict(l) for l in lignes]


def rechercher_audits(cible: str = "", limite: int = 10) -> list[dict]:
    """Historique des audits (mémoire à long terme), filtré par nom de cible, sans les rapports complets."""
    with connexion() as con:
        lignes = con.execute("SELECT id, date, cible, type, score, verdict, drive_lien FROM audits "
                             "WHERE cible LIKE ? ORDER BY id DESC LIMIT ?",
                             (f"%{cible}%", max(1, min(limite, 50)))).fetchall()
    return [dict(l) for l in lignes]


def lire_preferences() -> dict:
    with connexion() as con:
        lignes = con.execute("SELECT cle, valeur FROM preferences").fetchall()
    return {**PREFERENCES_DEFAUT, **{l["cle"]: l["valeur"] for l in lignes if l["cle"] in PREFERENCES_DEFAUT}}


def ecrire_preference(cle: str, valeur: str) -> None:
    if cle not in PREFERENCES_DEFAUT:
        raise ValueError(f"Préférence inconnue : {cle}")
    with connexion() as con:
        con.execute("INSERT OR REPLACE INTO preferences (cle, valeur, date) VALUES (?,?,?)", (cle, valeur, maintenant()))
    journaliser("preference", {"cle": cle})


def enregistrer_session(session_id: str | None, titre: str, audit_id: int | None = None) -> None:
    """Mémoire à court terme : mémorise une conversation pour pouvoir la reprendre (resume)."""
    if not session_id:
        return
    with connexion() as con:
        existe = con.execute("SELECT 1 FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if existe:
            con.execute("UPDATE sessions SET mise_a_jour = ?, messages = messages + 1 WHERE session_id = ?",
                        (maintenant(), session_id))
        else:
            con.execute("INSERT INTO sessions (session_id, titre, audit_id, creee, mise_a_jour) VALUES (?,?,?,?,?)",
                        (session_id, titre[:120], audit_id, maintenant(), maintenant()))


def completer_sessions_depuis_audits() -> None:
    """Rend reprenables les conversations des audits antérieurs à la table sessions."""
    with connexion() as con:
        con.execute("INSERT OR IGNORE INTO sessions (session_id, titre, audit_id, creee, mise_a_jour) "
                    "SELECT session_id, 'Audit n° ' || id || ' – ' || cible, id, date, date FROM audits "
                    "WHERE session_id IS NOT NULL")


def lister_sessions(limite: int = 15) -> list[dict]:
    with connexion() as con:
        lignes = con.execute("SELECT * FROM sessions ORDER BY mise_a_jour DESC LIMIT ?", (limite,)).fetchall()
    return [dict(l) for l in lignes]


def compter_evenements(evenement: str) -> int:
    with connexion() as con:
        return con.execute("SELECT COUNT(*) FROM journal WHERE evenement = ?", (evenement,)).fetchone()[0]


def compter_tables() -> dict:
    with connexion() as con:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                            "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}


def maj_envois_audit(audit_id: int, drive_lien: str | None, drive_statut: str, email_statut: str) -> None:
    """Mémorise le résultat de l'archivage Drive et de la notification e-mail d'un audit."""
    with connexion() as con:
        con.execute("UPDATE audits SET drive_lien = ?, drive_statut = ?, email_statut = ? WHERE id = ?",
                    (drive_lien, drive_statut, email_statut, audit_id))


def enregistrer_source(chemin: str, type_: str, url: str | None = None, commit_sha: str | None = None) -> None:
    """Origine d'un élément déposé ou importé (affichée dans la notification e-mail)."""
    with connexion() as con:
        con.execute("INSERT OR REPLACE INTO sources (chemin, type, url, commit_sha, date) VALUES (?,?,?,?,?)",
                    (chemin, type_, url, commit_sha, maintenant()))


def obtenir_source(chemin: str) -> dict | None:
    with connexion() as con:
        ligne = con.execute("SELECT * FROM sources WHERE chemin = ?", (chemin,)).fetchone()
    return dict(ligne) if ligne else None


def dernier_evenement(evenement: str, contient: str = "") -> dict | None:
    """Dernière entrée du journal pour un type d'événement (ex. résultat du dernier test d'un connecteur)."""
    with connexion() as con:
        ligne = con.execute("SELECT date, details FROM journal WHERE evenement = ? AND details LIKE ? "
                            "ORDER BY id DESC LIMIT 1", (evenement, f"%{contient}%")).fetchone()
    if not ligne:
        return None
    try:
        return {"date": ligne["date"], **json.loads(ligne["details"])}
    except (TypeError, ValueError):
        return {"date": ligne["date"], "details": ligne["details"]}


def obtenir_audit(audit_id: int) -> dict | None:
    with connexion() as con:
        ligne = con.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if not ligne:
        return None
    d = dict(ligne)
    d["donnees"] = json.loads(d["donnees"] or "{}")
    return d


def ajouter_alerte(cible: str, type_: str, message: str) -> None:
    with connexion() as con:
        con.execute("INSERT INTO alertes (date, cible, type, message) VALUES (?,?,?,?)",
                    (maintenant(), cible, type_, message))
    journaliser("alerte", {"cible": cible, "type": type_})


def lister_alertes(limite: int = 50) -> list[dict]:
    with connexion() as con:
        lignes = con.execute("SELECT * FROM alertes ORDER BY id DESC LIMIT ?", (limite,)).fetchall()
    return [dict(l) for l in lignes]
