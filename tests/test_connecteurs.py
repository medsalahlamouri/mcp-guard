"""Tests des connecteurs Gmail, Google Drive et GitHub : tous les appels réseau sont simulés (mock)."""
from __future__ import annotations

import json
import os
import unittest
import urllib.error
from datetime import datetime
from unittest import mock

import aide_tests

from backend import agent, connecteurs
from mcp_server import registry

DONNEES = {"type": "serveur_mcp", "score": 100, "niveau": "Critique", "verdict": "REJETER",
           "constats": [{"regle": "secret_en_dur", "gravite": "eleve", "points": 20, "owasp": "MCP01",
                         "titre": "Jeton GitHub écrit en dur", "tool": None, "ligne": 3,
                         "preuve": "server.py:3 → ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"},
                        {"regle": "exfiltration", "gravite": "critique", "points": 40, "owasp": "MCP10",
                         "titre": "Envoi de données", "tool": "sync", "ligne": 9, "preuve": "httpx.post(...)"}]}
SMTP_CONFIGURE = {"SMTP_UTILISATEUR": "expediteur@example.com", "SMTP_MOT_DE_PASSE": "mdp-application",
                  "ALERTE_DESTINATAIRE": "securite@example.com"}


def reponse_http(donnees: dict) -> mock.MagicMock:
    r = mock.MagicMock()
    r.__enter__.return_value.read.return_value = json.dumps(donnees).encode()
    return r


class TestContenu(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()

    def test_masquer_secrets(self):
        texte = connecteurs.masquer_secrets("jeton ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab et AKIAABCDEFGHIJKLMNOP")
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab", texte)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", texte)

    def test_sujet(self):
        self.assertEqual(connecteurs.construire_sujet("srv", "REJETER", 100),
                         "[MCP-Guard] 🚨 REJETER – srv – score 100/100")

    def test_corps_avec_et_sans_drive(self):
        quand = datetime(2026, 1, 2, 3, 4)
        avec = connecteurs.construire_corps(7, "samples/03", DONNEES, quand, {"lien": "https://drive/doc"})
        self.assertIn("Rapport complet (Google Drive) : https://drive/doc", avec)
        self.assertIn("1. [Critique] MCP10", avec)  # constat le plus grave en premier
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab", avec)  # secret masqué
        sans = connecteurs.construire_corps(7, "samples/03", DONNEES, quand, {"statut": "erreur", "message": "403"})
        self.assertIn("Archivage Google Drive indisponible (403)", sans)

    def test_rapport_de_secours(self):
        rapport = connecteurs.rapport_de_secours("samples/03", DONNEES)
        self.assertIn("**Verdict** : REJETER", rapport)
        self.assertIn("| Critique | MCP10 | sync |", rapport)
        self.assertIn("Aucun constat", connecteurs.rapport_de_secours("x", {"score": 0, "verdict": "INSTALLER"}))

    def test_decrire_source(self):
        self.assertIn("Échantillon", connecteurs.decrire_source("samples/01_serveur_sain"))
        self.assertIn("Copie installée", connecteurs.decrire_source("uploads/installes/meteo"))
        registry.enregistrer_source("uploads/github-o-d", "github", "https://github.com/o/d", "0123456789abcdef")
        self.assertIn("commit 0123456789ab", connecteurs.decrire_source("uploads/github-o-d/server.py"))
        self.assertIn("non enregistrée", connecteurs.decrire_source("uploads/inconnu"))


class TestApresAudit(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()
        self.audit_id = registry.enregistrer_audit("samples/03", "serveur_mcp", 100, "REJETER", "# R", DONNEES)

    def _apres(self, archiver: mock.MagicMock, envoyer: mock.MagicMock) -> dict:
        with mock.patch.dict(os.environ, {"DRIVE_ACTIVE": "1", "NOTIFICATION_CHAQUE_AUDIT": "1"}), \
                mock.patch.object(connecteurs, "drive_configure", return_value=True), \
                mock.patch.object(connecteurs, "archiver_rapport", archiver), \
                mock.patch.object(connecteurs, "envoyer_email", envoyer):
            return connecteurs.apres_audit(self.audit_id, "samples/03", DONNEES, "# Rapport de l'agent")

    def test_drive_puis_email(self):
        archiver = mock.MagicMock(
            return_value={"webViewLink": "https://drive/doc", "name": "r", "format": "Google Docs"})
        envoyer = mock.MagicMock(return_value={"envoye": True, "destinataire": "a@b.c"})
        r = self._apres(archiver, envoyer)
        self.assertEqual((r["drive"]["statut"], r["email"]["statut"]), ("ok", "ok"))
        self.assertIn("https://drive/doc", envoyer.call_args.args[1])  # le lien Drive est dans l'e-mail
        audit = registry.obtenir_audit(self.audit_id)
        self.assertEqual((audit["drive_lien"], audit["email_statut"]), ("https://drive/doc", "ok"))

    def test_echec_drive_n_empeche_pas_email(self):
        archiver = mock.MagicMock(side_effect=OSError("réseau coupé"))
        envoyer = mock.MagicMock(return_value={"envoye": False, "mode": "démonstration"})
        r = self._apres(archiver, envoyer)
        self.assertEqual((r["drive"]["statut"], r["email"]["statut"]), ("erreur", "démonstration"))
        self.assertIn("Archivage Google Drive indisponible", envoyer.call_args.args[1])
        self.assertFalse(registry.dernier_evenement("drive_envoi")["ok"])

    def test_echec_email_journalise(self):
        archiver = mock.MagicMock(return_value={"webViewLink": "l", "name": "r", "format": "Markdown"})
        envoyer = mock.MagicMock(side_effect=OSError("SMTP injoignable"))
        r = self._apres(archiver, envoyer)
        self.assertEqual(r["email"]["statut"], "erreur")
        self.assertIn("SMTP injoignable", registry.obtenir_audit(self.audit_id)["email_statut"])

    def test_tout_desactive(self):
        r = connecteurs.apres_audit(self.audit_id, "samples/03", DONNEES, "")  # DRIVE_ACTIVE=0 dans aide_tests
        self.assertEqual((r["drive"]["statut"], r["email"]["statut"]), ("désactivé", "désactivé"))


class TestGmail(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()
        self.outbox = aide_tests.nouveau_dossier("outbox")

    def test_mode_demonstration_sans_smtp(self):
        with mock.patch.object(agent, "OUTBOX", self.outbox), mock.patch("smtplib.SMTP_SSL") as smtp:
            r = agent.envoyer_email("Sujet", "Corps")
        smtp.assert_not_called()
        self.assertFalse(r["envoye"])
        self.assertEqual(len(list(self.outbox.glob("*.eml"))), 1)

    def test_envoi_smtp_tls_verifie(self):
        with mock.patch.dict(os.environ, SMTP_CONFIGURE), mock.patch("smtplib.SMTP_SSL") as smtp:
            r = agent.envoyer_email("Sujet", "Corps")
        self.assertEqual(r, {"envoye": True, "destinataire": "securite@example.com"})
        self.assertIsNotNone(smtp.call_args.kwargs["context"])  # certificat TLS vérifié
        session = smtp.return_value.__enter__.return_value
        session.login.assert_called_once_with("expediteur@example.com", "mdp-application")
        session.send_message.assert_called_once()

    def test_destinataire_des_preferences_prioritaire(self):
        registry.ecrire_preference("email_notification", "pref@example.com")
        with mock.patch.dict(os.environ, SMTP_CONFIGURE), mock.patch("smtplib.SMTP_SSL"):
            self.assertEqual(agent.envoyer_email("S", "C")["destinataire"], "pref@example.com")

    def test_tester_gmail_sans_envoi(self):
        with mock.patch.dict(os.environ, SMTP_CONFIGURE), mock.patch("smtplib.SMTP_SSL") as smtp:
            r = connecteurs.tester("gmail")
        self.assertTrue(r["ok"])
        smtp.return_value.__enter__.return_value.send_message.assert_not_called()

    def test_tester_gmail_non_configure(self):
        r = connecteurs.tester("gmail")
        self.assertFalse(r["ok"])
        self.assertIn("SMTP_UTILISATEUR", r["message"])
        self.assertFalse(registry.dernier_evenement("test_connecteur")["ok"])


class TestGitHub(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()

    def test_entetes(self):
        self.assertNotIn("Authorization", connecteurs.entetes_github())
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "jeton"}):
            self.assertEqual(connecteurs.entetes_github()["Authorization"], "Bearer jeton")

    def test_quota(self):
        corps = {"resources": {"core": {"remaining": 59, "limit": 60, "reset": 0}}}
        with mock.patch("urllib.request.urlopen", return_value=reponse_http(corps)):
            self.assertIn("59/60", connecteurs.tester("github")["message"])

    def test_quota_epuise(self):
        corps = {"resources": {"core": {"remaining": 0, "limit": 60, "reset": 0}}}
        with mock.patch("urllib.request.urlopen", return_value=reponse_http(corps)):
            r = connecteurs.tester("github")
        self.assertFalse(r["ok"])
        self.assertIn("quota API épuisé", r["message"])

    def test_jeton_invalide(self):
        erreur = urllib.error.HTTPError("u", 401, "Unauthorized", {}, None)
        self.addCleanup(erreur.close)
        with mock.patch("urllib.request.urlopen", side_effect=erreur):
            self.assertIn("GITHUB_TOKEN invalide", connecteurs.tester("github")["message"])


class TestDrive(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()

    def test_non_configure(self):
        self.assertFalse(connecteurs.drive_configure())
        r = connecteurs.tester("drive")
        self.assertFalse(r["ok"])
        self.assertIn("absent", r["message"])

    def test_aller_retour_supprime_le_fichier(self):
        service = mock.MagicMock()
        fichiers = service.files.return_value
        fichiers.get.return_value.execute.return_value = {"id": "f1",
                                                          "mimeType": "application/vnd.google-apps.document"}
        with mock.patch.object(connecteurs, "drive_configure", return_value=True), \
                mock.patch.object(connecteurs, "service_drive", return_value=service), \
                mock.patch.object(connecteurs, "dossier_racine", return_value="racine"), \
                mock.patch.object(connecteurs, "televerser_markdown", return_value={"id": "f1"}):
            r = connecteurs.tester("drive")
        self.assertTrue(r["ok"], r)
        fichiers.delete.assert_called_once_with(fileId="f1")

    def test_etat_connecteurs(self):
        etat = connecteurs.etat_connecteurs()
        self.assertEqual(set(etat), {"gmail", "drive", "github"})
        self.assertEqual(etat["drive"]["statut"], "non configuré")
        self.assertEqual(etat["github"]["detail"], "anonyme (60 requêtes/h)")


if __name__ == "__main__":
    unittest.main()
