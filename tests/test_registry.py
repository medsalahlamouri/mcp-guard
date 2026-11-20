"""Tests de la mémoire à long terme (SQLite) : base temporaire, jamais data/mcp_guard.db."""
from __future__ import annotations

import sqlite3
import unittest

import aide_tests

from mcp_server import registry

TABLES = {"serveurs_approuves", "audits", "alertes", "journal", "sources", "preferences", "sessions"}


class TestRegistry(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()

    def test_creation_des_tables(self):
        self.assertEqual(set(registry.compter_tables()), TABLES)
        self.assertTrue(all(n == 0 for n in registry.compter_tables().values()))

    def test_migration_douce_des_colonnes(self):
        """Une base de la première version (sans colonnes Drive/e-mail) est complétée sans perte."""
        con = sqlite3.connect(registry.DB_PATH)
        con.execute("CREATE TABLE audits (id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL, "
                    "cible TEXT NOT NULL, "
                    "type TEXT, score INTEGER, verdict TEXT, rapport TEXT, donnees TEXT, "
                    "session_id TEXT, cout_usd REAL)")
        con.execute("INSERT INTO audits (date, cible) VALUES ('2025-01-01', 'ancien')")
        con.commit()
        con.close()
        registry.maj_envois_audit(1, "https://drive/x", "ok", "ok")
        audit = registry.obtenir_audit(1)
        self.assertEqual((audit["cible"], audit["drive_lien"]), ("ancien", "https://drive/x"))

    def test_audits(self):
        id_ = registry.enregistrer_audit("samples/02", "serveur_mcp", 100, "REJETER", "# Rapport",
                                         {"constats": [{"regle": "x"}]}, "sess-1", 0.12)
        registry.enregistrer_audit("samples/01", "serveur_mcp", 0, "INSTALLER", "", {})
        audit = registry.obtenir_audit(id_)
        self.assertEqual((audit["verdict"], audit["donnees"]["constats"][0]["regle"]), ("REJETER", "x"))
        self.assertIsNone(registry.obtenir_audit(999))
        self.assertEqual([a["cible"] for a in registry.lister_audits()], ["samples/01", "samples/02"])
        self.assertEqual([a["id"] for a in registry.rechercher_audits("02")], [id_])
        registry.maj_envois_audit(id_, "https://drive/r", "ok", "démonstration")
        self.assertEqual(registry.lister_audits()[1]["email_statut"], "démonstration")

    def test_serveurs_approuves_et_empreintes(self):
        empreinte = {"empreinte_tools": "a" * 64, "empreinte_fichiers": "b" * 64, "tools": {"meteo": "c" * 16}}
        registry.approuver("meteo", "uploads/installes/meteo", empreinte)
        approuve = registry.obtenir_approuve("meteo")
        self.assertEqual(approuve["empreinte"], empreinte)  # dict relu à l'identique
        self.assertEqual(approuve["statut"], "approuvé")
        registry.changer_statut("meteo", "suspendu (rug pull)")
        self.assertEqual(registry.lister_approuves()[0]["statut"], "suspendu (rug pull)")
        self.assertIsNone(registry.obtenir_approuve("inconnu"))
        self.assertEqual(registry.compter_evenements("approbation"), 1)

    def test_preferences(self):
        self.assertEqual(registry.lire_preferences(), registry.PREFERENCES_DEFAUT)
        registry.ecrire_preference("niveau_detail", "détaillé")
        self.assertEqual(registry.lire_preferences()["niveau_detail"], "détaillé")
        with self.assertRaises(ValueError):
            registry.ecrire_preference("inconnue", "x")

    def test_sessions(self):
        registry.enregistrer_session(None, "ignorée")
        registry.enregistrer_session("s1", "Première question")
        registry.enregistrer_session("s1", "Suite")
        sessions = registry.lister_sessions()
        self.assertEqual(len(sessions), 1)
        self.assertEqual((sessions[0]["titre"], sessions[0]["messages"]), ("Première question", 2))

    def test_sessions_completees_depuis_audits(self):
        registry.enregistrer_audit("samples/01", "serveur_mcp", 0, "INSTALLER", "", {}, "sess-audit")
        registry.completer_sessions_depuis_audits()
        registry.completer_sessions_depuis_audits()  # idempotent
        self.assertEqual([s["session_id"] for s in registry.lister_sessions()], ["sess-audit"])

    def test_alertes_journal_sources(self):
        registry.ajouter_alerte("meteo", "rug_pull", "modifié")
        self.assertEqual(registry.lister_alertes()[0]["type"], "rug_pull")
        registry.journaliser("test_connecteur", {"connecteur": "gmail", "ok": True})
        self.assertTrue(registry.dernier_evenement("test_connecteur", '"connecteur": "gmail"')["ok"])
        self.assertIsNone(registry.dernier_evenement("test_connecteur", '"connecteur": "drive"'))
        registry.journaliser("texte_brut", "pas du JSON")
        self.assertEqual(registry.dernier_evenement("texte_brut")["details"], "pas du JSON")
        registry.enregistrer_source("uploads/x", "github", "https://github.com/o/d", "abc123")
        self.assertEqual(registry.obtenir_source("uploads/x")["commit_sha"], "abc123")
        self.assertIsNone(registry.obtenir_source("uploads/y"))

    def test_injection_sql_inoffensive(self):
        """Les valeurs sont toujours passées en paramètres, jamais concaténées."""
        registry.enregistrer_audit("x'); DROP TABLE audits; --", "serveur_mcp", 0, "INSTALLER", "", {})
        self.assertEqual(registry.rechercher_audits("' OR '1'='1"), [])
        self.assertIn("audits", registry.compter_tables())


if __name__ == "__main__":
    unittest.main()
