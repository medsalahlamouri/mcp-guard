"""Tests de sécurité de l'API FastAPI (TestClient) : aucun appel à l'agent, aucun envoi, base temporaire."""
from __future__ import annotations

import time
import unittest
import urllib.error
from unittest import mock

import aide_tests
from fastapi.testclient import TestClient

from backend import app as module_app
from backend import config, securite
from backend.routes import audits as routes_audits

securite.DELAI_ECHEC = 0  # pas de pause après un mot de passe faux pendant les tests

ROUTES_PROTEGEES = [
    ("get", "/api/session"), ("get", "/api/elements"), ("get", "/api/sessions"), ("get", "/api/preferences"),
    ("put", "/api/preferences"), ("get", "/api/approuves"), ("get", "/api/planification"),
    ("post", "/api/planification/executer"), ("get", "/api/audits"), ("get", "/api/audits/1"),
    ("get", "/api/audits/1/rapport.md"), ("get", "/api/alertes"), ("get", "/api/connecteurs"),
    ("get", "/api/fonctionnalites"), ("get", "/api/knowledge?q=owasp"), ("post", "/api/audit"),
    ("post", "/api/dialogue"), ("post", "/api/approuver"), ("post", "/api/import-github"),
    ("post", "/api/alerte/1"), ("post", "/api/demo/mise-a-jour-malveillante"),
    ("post", "/api/fonctionnalites/tools/tester"), ("post", "/api/connecteurs/github/tester"),
]


def client_connecte() -> TestClient:
    client = TestClient(module_app.app)
    r = client.post("/api/connexion", json={"mot_de_passe": aide_tests.MOT_DE_PASSE_TEST})
    assert r.status_code == 200, r.text
    return client


class TestAuthentification(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()
        self.anonyme = TestClient(module_app.app)

    def test_page_publique(self):
        r = self.anonyme.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r.headers["content-type"])
        self.assertIn('href="style.css"', r.text)
        self.assertIn('src="app.js"', r.text)
        for url, type_ in (("/style.css", "text/css"), ("/app.js", "text/javascript")):
            with self.subTest(url=url):
                r = self.anonyme.get(url)
                self.assertEqual(r.status_code, 200)
                self.assertIn(type_, r.headers["content-type"])

    def test_routes_refusees_sans_session(self):
        for methode, url in ROUTES_PROTEGEES:
            with self.subTest(url=url):
                r = getattr(self.anonyme, methode)(url, **({"json": {}} if methode in ("post", "put") else {}))
                self.assertEqual(r.status_code, 401)

    def test_depot_refuse_sans_session(self):
        r = self.anonyme.post("/api/depot", data={"nom": "x"}, files=[("fichiers", ("a.py", b"x = 1"))])
        self.assertEqual(r.status_code, 401)

    def test_jeton_invente_refuse(self):
        self.anonyme.cookies.set(securite.COOKIE, "jeton-invente")
        self.assertEqual(self.anonyme.get("/api/session").status_code, 401)

    def test_mauvais_mot_de_passe(self):
        r = self.anonyme.post("/api/connexion", json={"mot_de_passe": "faux"})
        self.assertEqual(r.status_code, 401)
        self.assertNotIn(securite.COOKIE, r.cookies)

    def test_connexion_cookie_securise_puis_deconnexion(self):
        r = self.anonyme.post("/api/connexion", json={"mot_de_passe": aide_tests.MOT_DE_PASSE_TEST})
        self.assertEqual(r.status_code, 200)
        entete = r.headers["set-cookie"].lower()
        self.assertIn("httponly", entete)
        self.assertIn("samesite=strict", entete)
        self.assertEqual(self.anonyme.get("/api/session").status_code, 200)
        self.anonyme.post("/api/deconnexion")
        self.assertEqual(self.anonyme.get("/api/session").status_code, 401)

    def test_cookie_avec_duree_de_vie(self):
        r = self.anonyme.post("/api/connexion", json={"mot_de_passe": aide_tests.MOT_DE_PASSE_TEST})
        self.assertIn(f"max-age={securite.DUREE_SESSION}", r.headers["set-cookie"].lower())

    def test_session_expiree(self):
        client = client_connecte()
        with mock.patch.object(securite.time, "monotonic", return_value=time.monotonic() + securite.DUREE_SESSION + 1):
            self.assertEqual(client.get("/api/session").status_code, 401)

    def test_nombre_de_sessions_borne(self):
        for _ in range(securite.MAX_SESSIONS + 5):
            securite.creer_session()
        self.assertLessEqual(len(securite._sessions), securite.MAX_SESSIONS)

    def test_mot_de_passe_accentue_sans_erreur_500(self):
        r = self.anonyme.post("/api/connexion", json={"mot_de_passe": "épée-à-clé"})
        self.assertEqual(r.status_code, 401)

    def test_corps_invalide_422_et_non_500(self):
        client = client_connecte()
        r = client.post("/api/audit", content=b"pas du json", headers={"Content-Type": "application/json"})
        self.assertEqual(r.status_code, 422)

    def test_fichiers_interface_en_liste_blanche(self):
        self.assertEqual(self.anonyme.get("/index.ancien.html").status_code, 404)
        self.assertEqual(self.anonyme.get("/.env").status_code, 404)
        self.assertEqual(self.anonyme.get("/%2E%2E%2F.env").status_code, 404)


class TestPerimetre(unittest.TestCase):
    """Seuls samples/ et uploads/ sont accessibles (anti path traversal) ; l'agent n'est jamais appelé."""

    def setUp(self):
        aide_tests.nouvelle_base()
        self.client = client_connecte()

    def test_audit_hors_perimetre_refuse(self):
        with mock.patch.object(routes_audits, "interroger_agent") as agent:
            for chemin in ("../.env", "samples/../.env", "backend", "C:/Windows/System32", "/etc/passwd", ""):
                with self.subTest(chemin=chemin):
                    self.assertEqual(self.client.post("/api/audit", json={"chemin": chemin}).status_code, 400)
        agent.assert_not_called()

    def test_approbation_hors_perimetre_refusee(self):
        self.assertEqual(self.client.post("/api/approuver", json={"chemin": "../credentials.json"}).status_code, 400)

    def test_approbation_refusee_si_verdict_rejeter(self):
        r = self.client.post("/api/approuver", json={"chemin": "samples/02_serveur_empoisonne", "nom": "x"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("REJETER", r.json()["detail"])

    def test_elements_listes(self):
        chemins = [e["chemin"] for e in self.client.get("/api/elements").json()]
        self.assertIn("samples/01_serveur_sain", chemins)


class TestDepot(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()
        self.client = client_connecte()
        self.uploads = aide_tests.nouveau_dossier("uploads")
        self.patch = mock.patch.object(config, "UPLOADS", self.uploads)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def deposer(self, nom: str, fichiers: list[tuple[str, bytes]]):
        return self.client.post("/api/depot", data={"nom": nom},
                                files=[("fichiers", (n, c)) for n, c in fichiers])

    def test_depot_valide(self):
        r = self.deposer("mon serveur", [("server.py", b"x = 1"), ("config.json", b"{}")])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["chemin"], "uploads/mon-serveur")
        self.assertTrue((self.uploads / "mon-serveur" / "server.py").exists())

    def test_nom_de_fichier_nettoye(self):
        r = self.deposer("srv", [("../../evil.py", b"x = 1")])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue((self.uploads / "srv" / "evil.py").exists())
        self.assertFalse((self.uploads.parent / "evil.py").exists())

    def test_taille_limitee(self):
        r = self.deposer("gros", [("gros.py", b"#" * (config.TAILLE_MAX + 1))])
        self.assertEqual(r.status_code, 400)
        self.assertIn("1 Mo", r.json()["detail"])

    def test_extension_refusee(self):
        r = self.deposer("bin", [("virus.exe", b"MZ"), ("script.sh", b"rm -rf /")])
        self.assertEqual(r.status_code, 400)
        self.assertFalse((self.uploads / "bin").exists() and any((self.uploads / "bin").iterdir()))

    def test_melange_valide_et_refuse_n_ecrit_rien(self):
        r = self.deposer("mixte", [("server.py", b"x = 1"), ("virus.exe", b"MZ")])
        self.assertEqual(r.status_code, 400)
        self.assertIn("virus.exe", r.json()["detail"])
        self.assertFalse((self.uploads / "mixte").exists())

    def test_trop_gros_apres_un_valide_n_ecrit_rien(self):
        r = self.deposer("partiel", [("a.py", b"x = 1"), ("b.py", b"#" * (config.TAILLE_MAX + 1))])
        self.assertEqual(r.status_code, 400)
        self.assertFalse((self.uploads / "partiel").exists())

    def test_chemin_windows_nettoye(self):
        r = self.deposer("win", [(r"..\..\evil.py", b"x = 1")])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["fichiers"], ["evil.py"])

    def test_trop_de_fichiers(self):
        r = self.deposer("n", [(f"f{i}.py", b"x") for i in range(21)])
        self.assertEqual(r.status_code, 400)

    def test_nom_reserve(self):
        self.assertEqual(self.deposer("installes", [("a.py", b"x")]).status_code, 400)


class TestImportGitHub(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()
        self.client = client_connecte()

    def test_url_invalide(self):
        for url in ("", "https://gitlab.com/o/d", "github.com/../../etc", "javascript:alert(1)",
                    "https://github.com/o/d/blob/main/x.py", "https://evil.com/github.com/o/d"):
            with self.subTest(url=url), mock.patch("urllib.request.urlopen"):
                self.assertEqual(self.client.post("/api/import-github", json={"url": url}).status_code, 400)

    def test_formats_d_url_acceptes(self):
        from backend.routes.elements import analyser_url_github
        self.assertEqual(analyser_url_github("https://github.com/org/depot"), ("org", "depot", None, ""))
        self.assertEqual(analyser_url_github("github.com/org/depot.git"), ("org", "depot", None, ""))
        self.assertEqual(analyser_url_github("https://github.com/org/depot?tab=readme-ov-file"),
                         ("org", "depot", None, ""))
        self.assertEqual(analyser_url_github("https://github.com/org/depot/tree/main/src/serveur/"),
                         ("org", "depot", "main", "src/serveur"))

    def test_remontee_dans_le_chemin_refusee(self):
        for url in ("https://github.com/org/depot/tree/main/../../user", "https://github.com/org/../tree/x"):
            with self.subTest(url=url), mock.patch("urllib.request.urlopen") as reseau:
                self.assertEqual(self.client.post("/api/import-github", json={"url": url}).status_code, 400)
                reseau.assert_not_called()

    def test_depot_sans_fichier_analysable(self):
        uploads = aide_tests.nouveau_dossier("uploads_vide")
        with mock.patch("backend.routes.elements.telecharger_depot", return_value=[]), \
                mock.patch.object(config, "UPLOADS", uploads):
            r = self.client.post("/api/import-github", json={"url": "https://github.com/org/vide"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(list(uploads.iterdir()), [])  # dossier vide supprimé

    def test_depot_introuvable(self):
        erreur = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        self.addCleanup(erreur.close)
        with mock.patch("urllib.request.urlopen", side_effect=erreur), \
                mock.patch.object(config, "UPLOADS", aide_tests.nouveau_dossier("uploads_gh")):
            r = self.client.post("/api/import-github", json={"url": "https://github.com/org/absent"})
        self.assertEqual(r.status_code, 502)
        self.assertIn("introuvable", r.json()["detail"])


class TestAutresRoutes(unittest.TestCase):
    def setUp(self):
        aide_tests.nouvelle_base()
        self.client = client_connecte()

    def test_preferences_validees(self):
        self.assertEqual(self.client.put("/api/preferences", json={"niveau_detail": "extrême"}).status_code, 400)
        r = self.client.put("/api/preferences", json={"email_notification": "pas-un-mail"})
        self.assertEqual(r.status_code, 400)
        r = self.client.put("/api/preferences", json={"niveau_detail": "détaillé", "email_notification": "a@b.tn"})
        self.assertEqual(r.json()["niveau_detail"], "détaillé")

    def test_audit_inconnu(self):
        self.assertEqual(self.client.get("/api/audits/999").status_code, 404)
        self.assertEqual(self.client.get("/api/audits/999/rapport.md").status_code, 404)

    def test_knowledge(self):
        self.assertEqual(self.client.get("/api/knowledge?q=").status_code, 400)
        r = self.client.get("/api/knowledge", params={"q": "tool poisoning"})
        self.assertIn("MCP03", r.json()[0]["titre"])

    def test_fonctionnalite_et_connecteur_inconnus(self):
        self.assertEqual(self.client.post("/api/fonctionnalites/inconnue/tester").status_code, 404)
        self.assertEqual(self.client.post("/api/connecteurs/slack/tester").status_code, 404)

    def test_dialogue_vide(self):
        self.assertEqual(self.client.post("/api/dialogue", json={"message": "   "}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
