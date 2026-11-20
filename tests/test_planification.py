"""Tests de la tâche planifiée (bonus) : ré-audit sans LLM, détection du rug pull, suspension et alerte."""
from __future__ import annotations

import shutil
import unittest
from unittest import mock

import aide_tests
from fastapi.testclient import TestClient

from backend import planification, securite
from backend.app import app
from mcp_server import analyzers as az
from mcp_server import registry

SAIN = aide_tests.ROOT / "samples" / "01_serveur_sain" / "server.py"
MODIFIE = aide_tests.ROOT / "samples" / "05_serveur_sain_modifie" / "server.py"


class TestReauditPlanifie(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()
        self.zone = aide_tests.nouveau_dossier("installes")
        self.installe = self.zone / "meteo"
        self.installe.mkdir()
        shutil.copy2(SAIN, self.installe / "server.py")
        registry.approuver("meteo", str(self.installe), az.empreinte(self.installe))
        # La copie installée est hors de samples/ et uploads/ : on autorise le dossier temporaire.
        for patch in (mock.patch.object(az, "ZONES_AUTORISEES", [self.zone]),
                      mock.patch.object(planification, "envoyer_email")):
            self.addCleanup(patch.stop)
            patch.start()
        self.email = planification.envoyer_email

    def test_aucune_modification(self):
        bilan = planification.reaudit_planifie()
        self.assertEqual((bilan["verifies"], bilan["rug_pulls"]), (1, []))
        self.assertEqual(registry.lister_approuves()[0]["statut"], "approuvé")
        self.email.assert_not_called()

    def test_rug_pull_suspendu_alerte_et_email(self):
        shutil.copy2(MODIFIE, self.installe / "server.py")  # « mise à jour » silencieuse
        bilan = planification.reaudit_planifie()
        self.assertEqual([r["nom"] for r in bilan["rug_pulls"]], ["meteo"])
        self.assertEqual(registry.lister_approuves()[0]["statut"], "suspendu (rug pull)")
        alerte = registry.lister_alertes()[0]
        self.assertEqual(alerte["type"], "rug_pull")
        self.assertIn("synchroniser_cache", alerte["message"])
        self.assertIn("Rug pull détecté : meteo", self.email.call_args.args[0])
        # Un serveur suspendu n'est plus revérifié tant qu'il n'est pas réaudité et réapprouvé.
        self.assertEqual(planification.reaudit_planifie()["verifies"], 0)

    def test_echec_email_n_interrompt_pas(self):
        shutil.copy2(MODIFIE, self.installe / "server.py")
        self.email.side_effect = OSError("SMTP injoignable")
        self.assertEqual(len(planification.reaudit_planifie()["rug_pulls"]), 1)
        self.assertEqual(registry.dernier_evenement("echec_email")["details"], "OSError : SMTP injoignable")

    def test_serveur_disparu_signale(self):
        shutil.rmtree(self.installe)
        bilan = planification.reaudit_planifie()
        self.assertEqual(bilan["rug_pulls"], [])
        self.assertEqual(registry.lister_alertes()[0]["type"], "erreur_reaudit")

    def test_route_executer(self):
        client = TestClient(app)
        client.post("/api/connexion", json={"mot_de_passe": aide_tests.MOT_DE_PASSE_TEST})
        self.assertEqual(client.post("/api/planification/executer").json()["verifies"], 1)
        securite.fermer_session(client.cookies.get(securite.COOKIE))


class TestDemarrage(unittest.TestCase):
    def test_mode_demonstration_et_mode_quotidien(self):
        for env, attendu in (({"MCPGUARD_REAUDIT_MINUTES": "2"}, "interval[0:02:00]"),
                             ({"MCPGUARD_REAUDIT_MINUTES": "0", "MCPGUARD_REAUDIT_HEURE": "7"}, "hour='7'")):
            with self.subTest(env=env), mock.patch.dict("os.environ", env), \
                    mock.patch.object(planification.planificateur, "start"):
                planification.demarrer()
                self.assertIn(attendu, str(planification.planificateur.get_job(planification.ID_TACHE).trigger))
                planification.planificateur.remove_job(planification.ID_TACHE)


if __name__ == "__main__":
    unittest.main()
