"""Tests du plugin osv-scanner : extraction statique des dépendances, requêtes OSV.dev simulées."""
from __future__ import annotations

import importlib.util
import json
import unittest
from unittest import mock

import aide_tests

_spec = importlib.util.spec_from_file_location("serveur_osv",
                                               aide_tests.ROOT / "plugin" / "osv-scanner" / "serveur_osv.py")
osv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(osv)


def dependances(fichiers: dict[str, str]) -> dict[str, dict]:
    dossier = aide_tests.nouveau_dossier("deps")
    for nom, contenu in fichiers.items():
        (dossier / nom).write_text(contenu, encoding="utf-8")
    return {d["paquet"]: d for d in osv.extraire_dependances(dossier)}


class TestExtraction(unittest.TestCase):
    def test_requirements(self):
        deps = dependances({"requirements.txt": "requests==2.19.0\nflask>=2\n# commentaire\n-e .\n"
                                                "git+https://x/y.git\nuvicorn[standard]==0.30.1  # serveur\n"})
        self.assertEqual(deps["requests"]["version"], "2.19.0")
        self.assertEqual(deps["flask"]["version"], "")  # contrainte non exacte : version non fixée
        self.assertEqual(deps["uvicorn"]["version"], "0.30.1")
        self.assertEqual(len(deps), 3)

    def test_requirements_aplati_par_import_github(self):
        self.assertIn("httpx", dependances({"src__requirements-dev.txt": "httpx==0.27.0\n"}))

    def test_pyproject(self):
        deps = dependances({"pyproject.toml": '[project]\ndependencies = ["pydantic==2.7.0", "rich"]\n'
                                              '[tool.poetry.dependencies]\npython = "^3.11"\nclick = "^8"\n'})
        self.assertEqual(deps["pydantic"]["version"], "2.7.0")
        self.assertIn("rich", deps)
        self.assertIn("click", deps)
        self.assertNotIn("python", deps)

    def test_package_json(self):
        deps = dependances({"package.json": json.dumps({"dependencies": {"express": "4.17.1", "lodash": "^4.17.0"},
                                                        "devDependencies": {"jest": "29.0.0"}})})
        self.assertEqual((deps["express"]["ecosysteme"], deps["express"]["version"]), ("npm", "4.17.1"))
        self.assertEqual(deps["lodash"]["version"], "")  # plage ^ : version non fixée
        self.assertIn("jest", deps)

    def test_imports_python(self):
        deps = dependances({"server.py": "import os, json\nimport yaml\nfrom outils import f\nimport httpx\n",
                            "outils.py": "def f(): pass\n"})
        self.assertIn("PyYAML", deps)  # nom du module -> nom du paquet PyPI
        self.assertIn("httpx", deps)
        self.assertNotIn("os", deps)  # bibliothèque standard ignorée
        self.assertNotIn("outils", deps)  # module local ignoré

    def test_fichier_mal_forme_ignore(self):
        deps = dependances({"package.json": "{pas du json", "pyproject.toml": "[[[",
                            "requirements.txt": "rich==13.0.0"})
        self.assertEqual(list(deps), ["rich"])

    def test_echantillon_jamais_execute(self):
        """L'extraction lit les fichiers sans les importer : l'échantillon vulnérable reste inerte."""
        deps = osv.extraire_dependances(aide_tests.ROOT / "samples" / "03_serveur_vulnerable")
        self.assertIsInstance(deps, list)


class TestRequetesOsv(unittest.TestCase):
    def test_interroger_osv(self):
        reponses = {"querybatch": {"results": [{"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]}, {}]},
                    "vulns/GHSA-1": {"aliases": ["CVE-1"], "summary": "faille 1"},
                    "vulns/GHSA-2": {"aliases": [], "summary": "faille 2"}}
        deps = [{"paquet": "requests", "version": "2.19.0", "ecosysteme": "PyPI", "origine": "r"},
                {"paquet": "rich", "version": "", "ecosysteme": "PyPI", "origine": "r"}]
        with mock.patch.object(osv, "_osv", side_effect=lambda chemin, corps=None: reponses[chemin]) as appel:
            r = osv.interroger_osv(deps)
        requete = appel.call_args_list[0].args[1]["queries"]
        self.assertEqual(requete[0]["version"], "2.19.0")
        self.assertNotIn("version", requete[1])  # pas de version : toutes les versions publiées
        self.assertEqual((r[0]["vulnerabilites"], r[0]["exemples"][0]["alias"]), (2, ["CVE-1"]))
        self.assertEqual((r[1]["vulnerabilites"], r[1]["version"]), (0, "non fixée"))

    def test_tool_refuse_hors_perimetre(self):
        with mock.patch.object(osv, "_osv") as appel:
            r = osv.analyser_dependances("../.env")
        self.assertIn("erreur", r)
        appel.assert_not_called()

    def test_tool_osv_injoignable(self):
        with mock.patch.object(osv, "_osv", side_effect=OSError("hors ligne")):
            r = osv.analyser_dependances("samples/05_serveur_sain_modifie")
        self.assertIn("OSV.dev injoignable", r["erreur"])
        self.assertTrue(r["dependances"])


if __name__ == "__main__":
    unittest.main()
