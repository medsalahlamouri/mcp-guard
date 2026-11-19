"""Test d'intégration du serveur MCP « mcp-guard » : vrai client MCP en stdio (tools/list + appels).

Aucun LLM, aucun réseau. Seuls des tools en lecture seule sont appelés : la base SQLite réelle n'est pas modifiée.
"""
from __future__ import annotations

import asyncio
import json
import sys
import unittest

import aide_tests
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

TOOLS_ATTENDUS = {
    "lister_elements_disponibles", "scanner_descriptions", "detecter_secrets", "analyser_code", "analyser_skill",
    "analyser_config_mcp", "audit_complet", "calculer_empreinte", "approuver_serveur", "verifier_rug_pull",
    "lister_serveurs_approuves", "consulter_historique_audits", "lister_alertes", "lire_preferences",
    "rechercher_knowledge", "verifier_vulnerabilites_osv",
}


def _donnees(resultat) -> dict | list:
    if resultat.structured_content:
        return resultat.structured_content
    return json.loads("".join(c.text for c in resultat.content if hasattr(c, "text")))


async def _session(appels: list[tuple[str, dict]]) -> tuple[set[str], dict]:
    params = StdioServerParameters(command=sys.executable, args=[str(aide_tests.ROOT / "mcp_server" / "server.py")],
                                   cwd=str(aide_tests.ROOT))
    async with stdio_client(params) as (lecture, ecriture), ClientSession(lecture, ecriture) as session:
        await session.initialize()
        noms = {t.name for t in (await session.list_tools()).tools}
        resultats = {nom: _donnees(await session.call_tool(nom, args)) for nom, args in appels}
    return noms, resultats


class TestServeurMcp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools, cls.r = asyncio.run(_session([
            ("audit_complet", {"chemin": "samples/01_serveur_sain"}),
            ("scanner_descriptions", {"chemin": "samples/02_serveur_empoisonne"}),
            ("detecter_secrets", {"chemin": "../.env"}),
            ("rechercher_knowledge", {"question": "tool poisoning", "nombre": 1}),
        ]))

    def test_seize_tools_exposes(self):
        self.assertEqual(self.tools, TOOLS_ATTENDUS)

    def test_audit_complet(self):
        self.assertEqual((self.r["audit_complet"]["verdict"], self.r["audit_complet"]["score"]), ("INSTALLER", 0))

    def test_tool_poisoning_detecte(self):
        self.assertIn("balise_cachee", json.dumps(self.r["scanner_descriptions"]))

    def test_perimetre_respecte(self):
        self.assertIn("PermissionError", self.r["detecter_secrets"]["erreur"])

    def test_knowledge(self):
        resultat = self.r["rechercher_knowledge"]
        premier = (resultat.get("result") if isinstance(resultat, dict) else resultat)[0]
        self.assertIn("MCP03", premier["titre"])


if __name__ == "__main__":
    unittest.main()
