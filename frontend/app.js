/* MCP-Guard : logique de l'interface (extraite de index.html, comportement inchangé).
   Script classique (non module) : les fonctions restent globales pour les attributs onclick du HTML. */
let elementSelectionne = null, sessionId = null, dernierAudit = null, elementsCharges = [];
const $ = (id) => document.getElementById(id);
const echap = (t) => String(t ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const icone = (nom, style = "") => `<svg class="ic" style="${style}"><use href="#i-${nom}"/></svg>`;
const libelleGravite = {critique:"Critique", eleve:"Élevée", moyen:"Moyenne", faible:"Faible", info:"Info"};
const VUES = {
  audit: ["Audit de sécurité", "Analysez un serveur MCP ou une skill avant de l'installer."],
  historique: ["Historique des audits", "Tous les audits enregistrés dans la mémoire à long terme."],
  approuves: ["Serveurs approuvés", "Serveurs installés et surveillés contre le rug pull."],
  planif: ["Planification et alertes", "Réaudit automatique et alertes de sécurité."],
  fonctionnalites: ["Fonctionnalités de l'agent", "Les 9 fonctionnalités de l'énoncé, leur justification et leur état en direct."],
  preferences: ["Préférences", "Vos réglages, mémorisés à long terme et respectés par l'agent."],
};

function markdownSur(texte) {
  // Le rapport peut citer du contenu malveillant issu des fichiers audités : on assainit le HTML (anti-XSS).
  if (window.marked && window.DOMPurify) return DOMPurify.sanitize(marked.parse(texte || ""));
  return "<pre>" + echap(texte) + "</pre>";
}

function messageErreur(donnees, statut) {
  // Toujours une chaîne lisible : évite l'affichage « [object Object] » quelle que soit la forme de l'erreur.
  const d = donnees && typeof donnees === "object" && !Array.isArray(donnees) ? (donnees.detail ?? donnees.message ?? donnees) : donnees;
  if (typeof d === "string" && d.trim()) return d.trim().slice(0, 500);
  if (Array.isArray(d)) return "Requête incomplète : " + d.map(x => `${(x.loc || []).slice(-1)[0] ?? "champ"} : ${x.msg ?? JSON.stringify(x)}`).join(" ; ");
  if (d && typeof d === "object") return JSON.stringify(d).slice(0, 500);
  return `Erreur HTTP ${statut}`;
}
async function api(url, options = {}) {
  let r;
  try { r = await fetch(url, options); }
  catch { throw new Error("Serveur MCP-Guard injoignable : vérifiez que « python run.py » tourne."); }
  if (r.status === 401) { afficherConnexion(); throw new Error("Session expirée"); }
  const type = r.headers.get("content-type") || "";
  const donnees = type.includes("json") ? await r.json().catch(() => null) : await r.text();
  if (!r.ok) throw new Error(messageErreur(donnees, r.status));
  return donnees;
}
const lienDriveSur = (l) => typeof l === "string" && /^https:\/\/(docs|drive)\.google\.com\//.test(l) ? l : null;
const post = (url, corps) => api(url, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(corps || {})});

/* ---------- Thème, notifications, fenêtre modale ---------- */
function basculerTheme() {
  const sombre = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = sombre ? "light" : "dark";
  try { localStorage.setItem("mcpguard-theme", document.documentElement.dataset.theme); } catch {}
}
try { const t = localStorage.getItem("mcpguard-theme"); if (t) document.documentElement.dataset.theme = t; } catch {}

function toast(message, type = "") {
  const t = document.createElement("div");
  t.className = "toast " + type;
  t.innerHTML = icone(type === "err" ? "alerte" : type === "ok" ? "check" : "bouclier",
    `color:var(${type === "err" ? "--crit" : type === "ok" ? "--ok" : "--accent"})`) + `<div>${echap(message)}</div>`;
  $("toasts").appendChild(t);
  setTimeout(() => t.remove(), 5500);
}

function demander({titre, texte, valeur = null, confirmer = "Confirmer", danger = false}) {
  return new Promise(resoudre => {
    $("modale-titre").textContent = titre; $("modale-texte").textContent = texte;
    const champ = $("modale-champ"), ok = $("modale-ok");
    champ.classList.toggle("cache", valeur === null); champ.value = valeur ?? "";
    ok.textContent = confirmer; ok.className = "btn " + (danger ? "danger" : "principal");
    $("modale").classList.remove("cache");
    (valeur === null ? ok : champ).focus();
    const fermer = (res) => { $("modale").classList.add("cache"); ok.onclick = $("modale-annuler").onclick = champ.onkeydown = null; resoudre(res); };
    ok.onclick = () => fermer(valeur === null ? true : champ.value.trim() || null);
    $("modale-annuler").onclick = () => fermer(null);
    champ.onkeydown = e => { if (e.key === "Enter") ok.onclick(); if (e.key === "Escape") fermer(null); };
  });
}

/* ---------- Connexion ---------- */
function afficherConnexion() { $("app").classList.add("cache"); $("connexion").classList.remove("cache"); $("mdp").focus(); }
async function seConnecter() {
  $("erreur-connexion").textContent = "";
  try { await post("/api/connexion", {mot_de_passe: $("mdp").value}); $("mdp").value = ""; demarrer(); }
  catch (e) { $("erreur-connexion").textContent = e.message; }
}
$("mdp").addEventListener("keydown", e => { if (e.key === "Enter") seConnecter(); });
async function seDeconnecter() { await post("/api/deconnexion"); afficherConnexion(); }

async function demarrer() {
  try { const s = await api("/api/session"); $("modele").textContent = "Agent Claude · " + s.modele; }
  catch { return; }
  $("connexion").classList.add("cache"); $("app").classList.remove("cache");
  afficherVue("audit");
  chargerElements();
  majCompteurAlertes();
  chargerConnecteurs();
  try { sessionId = localStorage.getItem("mcpguard-session") || null; } catch {}
  if (sessionId) $("info-session").textContent = "Conversation précédente restaurée (mémoire à court terme) : vous pouvez continuer.";
  chargerSessions();
  api("/api/fonctionnalites").then(c => { cartesFonc = c; majCompteurFonc(); }).catch(() => {});
}

/* ---------- Connecteurs (Gmail, Drive, GitHub) ---------- */
const NOMS_CONNECTEURS = {gmail: "Gmail", drive: "Google Drive", github: "GitHub"};
async function chargerConnecteurs() {
  try {
    const etat = await api("/api/connecteurs");
    $("liste-connecteurs").innerHTML = Object.entries(etat).map(([nom, c]) => {
      const info = c.dernier ? `${c.dernier.date} — ${c.dernier.message}` : c.detail;
      return `<div class="connecteur" data-nom="${echap(nom)}" title="${echap(info)}\nCliquer pour tester (aucun e-mail envoyé)">
        <span class="puce-etat ${echap(c.statut)}"></span><span>${echap(NOMS_CONNECTEURS[nom] || nom)}</span>
        <span class="etat ${echap(c.statut)}">${echap(c.statut === "ok" ? "testé ✓" : c.statut)}</span></div>`;
    }).join("");
    document.querySelectorAll(".connecteur").forEach(el => el.onclick = () => testerConnecteur(el.dataset.nom));
  } catch {}
}
async function testerConnecteur(nom) {
  try {
    const r = await post(`/api/connecteurs/${encodeURIComponent(nom)}/tester`);
    toast(`${NOMS_CONNECTEURS[nom]} : ${r.message}`, r.ok ? "ok" : "err");
  } catch (e) { toast(e.message, "err"); }
  chargerConnecteurs();
}
async function testerTousConnecteurs() { for (const n of Object.keys(NOMS_CONNECTEURS)) await testerConnecteur(n); }

/* ---------- Navigation ---------- */
function afficherVue(vue) {
  document.querySelectorAll("nav button[data-vue]").forEach(x => x.classList.toggle("actif", x.dataset.vue === vue));
  Object.keys(VUES).forEach(v => $("vue-" + v).classList.toggle("cache", v !== vue));
  $("titre-vue").textContent = VUES[vue][0]; $("sous-titre-vue").textContent = VUES[vue][1];
  if (vue === "historique") chargerHistorique();
  if (vue === "approuves") chargerApprouves();
  if (vue === "planif") chargerPlanif();
  if (vue === "fonctionnalites") chargerFonctionnalites();
  if (vue === "preferences") chargerPreferences();
}
document.querySelectorAll("nav button[data-vue]").forEach(b => b.onclick = () => afficherVue(b.dataset.vue));

document.querySelectorAll(".onglets button").forEach(b => b.onclick = () => {
  document.querySelectorAll(".onglets button").forEach(x => x.classList.toggle("actif", x === b));
  $("onglet-fichiers").classList.toggle("cache", b.dataset.onglet !== "fichiers");
  $("onglet-github").classList.toggle("cache", b.dataset.onglet !== "github");
  $("info-depot").textContent = "";
});

/* ---------- Éléments ---------- */
async function chargerElements() {
  elementsCharges = await api("/api/elements");
  filtrerElements();
}
function filtrerElements() {
  const f = $("filtre").value.trim().toLowerCase();
  const liste = elementsCharges.filter(e => !f || e.nom.toLowerCase().includes(f) || e.zone.toLowerCase().includes(f));
  $("elements").innerHTML = liste.map(e =>
    `<div class="element ${e.chemin === elementSelectionne ? "sel" : ""}" data-chemin="${echap(e.chemin)}">
       <span class="icone">${icone(e.zone === "installé" ? "serveur" : e.nom.includes("skill") ? "doc" : e.nom.includes("config") ? "fichier" : "dossier", "width:16px;height:16px")}</span>
       <span class="nom" title="${echap(e.chemin)}">${echap(e.nom)}</span><span class="zone ${echap(e.zone)}">${echap(e.zone)}</span></div>`).join("")
    || `<div class="note" style="padding:10px">Aucun élément.</div>`;
  document.querySelectorAll(".element").forEach(el => el.onclick = () => {
    document.querySelectorAll(".element").forEach(x => x.classList.remove("sel"));
    el.classList.add("sel"); elementSelectionne = el.dataset.chemin;
    $("selection").innerHTML = "Sélection : <code>" + echap(elementSelectionne) + "</code>";
  });
}

const zoneDepot = $("zone-depot");
$("fichiers").addEventListener("change", afficherFichiersChoisis);
["dragenter", "dragover"].forEach(ev => zoneDepot.addEventListener(ev, e => { e.preventDefault(); zoneDepot.classList.add("survol"); }));
["dragleave", "drop"].forEach(ev => zoneDepot.addEventListener(ev, e => { e.preventDefault(); zoneDepot.classList.remove("survol"); }));
zoneDepot.addEventListener("drop", e => { $("fichiers").files = e.dataTransfer.files; afficherFichiersChoisis(); });
function afficherFichiersChoisis() {
  const noms = [...$("fichiers").files].map(f => f.name);
  $("liste-fichiers").textContent = noms.length ? noms.join(" · ") : "";
}

async function deposer() {
  if (!$("fichiers").files.length) { $("info-depot").textContent = "Sélectionnez d'abord au moins un fichier."; return; }
  const fd = new FormData(); fd.append("nom", $("nom-depot").value || "depot");
  for (const f of $("fichiers").files) fd.append("fichiers", f);
  try {
    const r = await api("/api/depot", {method:"POST", body:fd});
    $("info-depot").textContent = "Déposé dans " + r.chemin; toast(`${r.fichiers.length} fichier(s) déposé(s) dans ${r.chemin}`, "ok");
    $("fichiers").value = ""; afficherFichiersChoisis(); chargerElements();
  } catch (e) { $("info-depot").textContent = e.message; toast(e.message, "err"); }
}
async function importerGithub() {
  $("info-depot").textContent = "Import en cours…";
  try {
    const r = await post("/api/import-github", {url: $("url-github").value});
    $("info-depot").textContent = `${r.fichiers.length} fichier(s) importé(s) dans ${r.chemin}` + (r.commit ? ` (commit ${r.commit.slice(0, 7)})` : "");
    toast($("info-depot").textContent, "ok"); chargerElements();
  } catch (e) { $("info-depot").textContent = e.message; toast(e.message, "err"); }
  chargerConnecteurs();
}

/* ---------- Audit ---------- */
async function lancerAudit() {
  if (!elementSelectionne) { $("selection").textContent = "Choisissez d'abord un élément dans la liste."; return; }
  $("btn-audit").disabled = true;
  const debut = Date.now();
  $("resultat").innerHTML = `<div class="attente"><div class="spinner"></div>
    <div><b style="color:var(--texte)">Audit de ${echap(elementSelectionne)} en cours…</b><br>L'agent appelle ses tools MCP puis rédige le rapport (environ 1 minute).</div>
    <span class="chrono" id="chrono">0 s</span></div>`;
  const minuteur = setInterval(() => { const c = $("chrono"); if (c) c.textContent = Math.round((Date.now() - debut) / 1000) + " s"; }, 1000);
  try {
    const r = await post("/api/audit", {chemin: elementSelectionne});
    dernierAudit = r; afficherResultat(r);
    definirSession(r.session_id, "Conversation liée à l'audit n° " + r.audit_id + " (mémoire à court terme).");
    $("chat").innerHTML = "";
    const e = r.envois || {};
    if (e.drive?.statut === "erreur" || e.email?.statut === "erreur") toast("Audit enregistré, mais un envoi a échoué (voir sous le résultat).", "err");
    else if (e.drive?.statut === "ok" || e.email?.statut === "ok") toast("Audit enregistré, archivé et notifié.", "ok");
    chargerConnecteurs();
  } catch (e) { $("resultat").innerHTML = `<div class="vide"><div class="illus" style="background:var(--crit-bg);color:var(--crit)">${icone("alerte")}</div><h3>Échec de l'audit</h3><div class="erreur">${echap(e.message)}</div></div>`; }
  clearInterval(minuteur);
  $("btn-audit").disabled = false;
}

function jauge(score, verdict) {
  const c = 2 * Math.PI * 50, plein = c * Math.max(0, Math.min(100, score)) / 100;
  return `<div class="jauge v-${verdict}"><svg width="118" height="118" viewBox="0 0 118 118">
      <circle cx="59" cy="59" r="50" fill="none" stroke="var(--neutre-bg)" stroke-width="10"/>
      <circle cx="59" cy="59" r="50" fill="none" stroke="var(--v)" stroke-width="10" stroke-linecap="round" stroke-dasharray="${plein} ${c}"/></svg>
    <div class="valeur"><b style="color:var(--v)">${score}</b><span>/ 100 risque</span></div></div>`;
}

function afficherResultat(r) {
  const d = r.donnees;
  const nb = g => d.constats.filter(c => c.gravite === g).length;
  const lignes = d.constats.map((c, i) => `<tr><td>${i + 1}</td><td><span class="badge ${c.gravite}">${libelleGravite[c.gravite]}</span></td>
    <td><b>${echap(c.owasp)}</b></td><td><code>${echap(c.tool || "-")}</code></td><td><b>${echap(c.titre)}</b><br><span class="note">${echap(c.explication)}</span></td>
    <td><code>${echap(c.preuve)}</code></td></tr>`).join("")
    || `<tr><td colspan="6" style="text-align:center;padding:18px"><span class="badge ok">${icone("check", "width:13px;height:13px")}Aucun constat</span></td></tr>`;
  const outils = (r.outils_utilises || []).map(o => `<span class="t">${echap(o.outil)}</span>`).join("");
  const cout = r.cout_equivalent_usd != null ? ` · coût équivalent API : ${r.cout_equivalent_usd.toFixed(3)} $ (non facturé, pris sur l'abonnement)` : "";
  const compteur = (lib, n, couleur) => `<div class="compteur-g"><div class="lib"><i style="background:var(${couleur})"></i>${lib}</div><div class="val">${n}</div></div>`;
  $("resultat").innerHTML = `
    <div class="carte-titre"><span class="num">2</span><h2>Résultat de l'audit n° ${r.audit_id}</h2></div>
    <div class="synthese">
      ${jauge(d.score, d.verdict)}
      <div>
        <span class="verdict v-${d.verdict}">${icone(d.verdict === "INSTALLER" ? "check" : "alerte", "width:15px;height:15px")}${d.verdict}</span>
        <h2>${echap(d.cible)}</h2>
        <div class="meta"><span>Type : <b>${echap((d.type || "").replace("_", " "))}</b></span><span>Niveau : <b>${echap(d.niveau)}</b></span>
          <span>Fichiers : <b>${(d.fichiers || []).length}</b></span><span>Tools détectés : <b>${(d.tools || []).length}</b></span>
          ${d.empreinte ? `<span>Empreinte : <code title="${echap(d.empreinte)}">${echap(d.empreinte.slice(0, 12))}…</code></span>` : ""}</div>
      </div>
    </div>
    <div class="compteurs">${compteur("Critiques", nb("critique"), "--crit")}${compteur("Élevés", nb("eleve"), "--eleve")}${compteur("Moyens", nb("moyen"), "--moyen")}${compteur("Faibles / info", nb("faible") + nb("info"), "--doux")}</div>
    <div class="barre-actions">
      <a class="btn" href="/api/audits/${r.audit_id}/rapport.md">${icone("dl")}Télécharger le rapport</a>
      <button class="btn" onclick="envoyerAlerte(${r.audit_id})">${icone("mail")}Envoyer l'alerte e-mail</button>
      ${d.verdict === "INSTALLER" ? `<button class="btn principal" onclick="approuver()">${icone("check")}Approuver et installer</button>` : ""}
    </div>
    ${blocEnvois(r.envois)}
    <div class="info-action" id="info-action"></div>
    <div class="tableau" style="margin-top:8px"><table><thead><tr><th>#</th><th>Gravité</th><th>OWASP</th><th>Tool</th><th>Constat</th><th>Preuve</th></tr></thead><tbody>${lignes}</tbody></table></div>
    <div class="trace">${icone("serveur", "width:14px;height:14px")}Tools appelés par l'agent : ${outils || "aucun"} · ${r.tours ?? "?"} tour(s)${cout}</div>
    <details class="bloc-rapport" open><summary>${icone("doc")}Rapport rédigé par l'agent</summary>
      <div class="rapport">${r.erreur ? `<div class="erreur" style="padding-top:12px">${echap(r.reponse)}</div>` : markdownSur(r.reponse)}</div></details>`;
}

function blocEnvois(envois) {
  if (!envois) return "";
  const d = envois.drive || {}, m = envois.email || {};
  const classe = s => s === "ok" ? "ok" : s === "erreur" ? "erreur" : "neutre";
  const lien = lienDriveSur(d.lien);
  const texteDrive = d.statut === "ok" && lien
    ? `<a href="${echap(lien)}" target="_blank" rel="noopener noreferrer">${echap(d.nom || "Ouvrir le rapport")}</a> (${echap(d.format || "")})`
    : echap(d.message || d.statut || "—");
  const texteMail = m.statut === "ok" ? `Envoyé à ${echap(m.destinataire)}`
    : m.statut === "démonstration" ? `SMTP non configuré : enregistré dans <code>${echap(m.fichier)}</code>`
    : echap(m.message || m.statut || "—");
  return `<div class="envois">
    <div class="envoi ${classe(d.statut)}">${icone("drive")}<div><b>Archivage Google Drive</b><span class="msg-envoi">${texteDrive}</span></div></div>
    <div class="envoi ${classe(m.statut === "démonstration" ? "neutre" : m.statut)}">${icone("mail")}<div><b>Notification e-mail</b><span class="msg-envoi">${texteMail}</span></div></div>
  </div>`;
}

async function envoyerAlerte(id) {
  try {
    const r = await post("/api/alerte/" + id);
    $("info-action").textContent = r.envoye ? "Alerte envoyée à " + r.destinataire : "Mode démonstration : e-mail enregistré dans " + r.fichier;
    toast($("info-action").textContent, "ok"); majCompteurAlertes();
  } catch (e) { $("info-action").textContent = e.message; toast(e.message, "err"); }
}
async function approuver() {
  const nom = await demander({titre:"Approuver et installer", texte:"Nom d'usage du serveur approuvé. Une copie sera installée et son empreinte mémorisée.", valeur:"meteo-tunisie", confirmer:"Approuver"});
  if (!nom) return;
  try {
    const r = await post("/api/approuver", {chemin: elementSelectionne, nom});
    $("info-action").textContent = `Approuvé et installé dans ${r.installe_dans}. Empreinte mémorisée.`; toast($("info-action").textContent, "ok"); chargerElements();
  } catch (e) { $("info-action").textContent = e.message; toast(e.message, "err"); }
}

/* ---------- Dialogue ---------- */
function ajouterMessage(role, html) { const d = document.createElement("div"); d.className = "msg " + role; d.innerHTML = html; $("chat").appendChild(d); $("chat").scrollTop = $("chat").scrollHeight; return d; }
document.querySelectorAll("#suggestions button").forEach(b => b.onclick = () => { $("message").value = b.textContent; $("message").focus(); });
async function envoyerMessage() {
  const texte = $("message").value.trim(); if (!texte) return;
  $("message").value = ""; ajouterMessage("u", echap(texte)); $("btn-message").disabled = true;
  const attente = ajouterMessage("a attente-msg", `<div class="spinner"></div>L'agent réfléchit…`);
  try {
    const r = await post("/api/dialogue", {message: texte, session_id: sessionId});
    if (r.session_id && r.session_id !== sessionId) definirSession(r.session_id);
    else chargerSessions();
    const outils = (r.outils_utilises || []).map(o => `<span class="t">${echap(o.outil)}</span>`).join("");
    attente.remove();
    ajouterMessage("a", markdownSur(r.reponse) + (outils ? `<div class="trace">Tools : ${outils}</div>` : ""));
    majCompteurAlertes();
  } catch (e) { attente.remove(); ajouterMessage("a", `<span class="erreur">${echap(e.message)}</span>`); }
  $("btn-message").disabled = false;
}
function nouvelleConversation() { definirSession(null, "Nouvelle conversation : l'agent repart sans contexte (seule la mémoire à long terme subsiste)."); $("chat").innerHTML = ""; }

/* ---------- Mémoire à court terme : session de conversation (conservée au rechargement de la page) ---------- */
function definirSession(id, info) {
  sessionId = id || null;
  try { id ? localStorage.setItem("mcpguard-session", id) : localStorage.removeItem("mcpguard-session"); } catch {}
  if (info) $("info-session").textContent = info;
  chargerSessions();
}
async function chargerSessions() {
  try {
    const l = await api("/api/sessions");
    $("sessions").innerHTML = `<option value="">Reprendre une conversation…</option>` + l.map(s =>
      `<option value="${echap(s.session_id)}" ${s.session_id === sessionId ? "selected" : ""}>${echap(s.titre.slice(0, 60))} · ${echap(s.mise_a_jour.slice(5, 16))}</option>`).join("");
  } catch {}
}
function reprendreSession(id) {
  if (!id) return;
  $("chat").innerHTML = "";
  definirSession(id, "Conversation reprise : l'agent se souvient de ses échanges précédents (posez votre question).");
  $("message").focus();
}

/* ---------- Préférences (mémoire à long terme) ---------- */
const DESCRIPTIONS_NIVEAUX = {
  "synthétique": "Synthèse, tableau des constats et décision. Idéal pour un tri rapide.",
  "standard": "Rapport complet au format de la skill rapport-audit-mcp.",
  "détaillé": "Scénarios d'attaque pas à pas, code corrigé complet, références OWASP.",
};
let niveauChoisi = "standard";
async function chargerPreferences() {
  const p = await api("/api/preferences");
  niveauChoisi = p.niveau_detail;
  $("choix-niveaux").innerHTML = p.niveaux.map(n => `<div class="niveau ${n === niveauChoisi ? "sel" : ""}" data-niveau="${echap(n)}">
    <b>${echap(n.charAt(0).toUpperCase() + n.slice(1))}</b>${echap(DESCRIPTIONS_NIVEAUX[n] || "")}</div>`).join("");
  document.querySelectorAll(".niveau").forEach(el => el.onclick = () => {
    niveauChoisi = el.dataset.niveau;
    document.querySelectorAll(".niveau").forEach(x => x.classList.toggle("sel", x === el));
  });
  $("pref-email").value = p.email_notification || "";
  $("info-email-defaut").textContent = p.email_par_defaut ? "Vide = adresse ALERTE_DESTINATAIRE du fichier .env (configurée)." : "Aucune adresse dans .env : renseignez-en une ici.";
}
async function enregistrerPreferences() {
  try {
    await api("/api/preferences", {method: "PUT", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({niveau_detail: niveauChoisi, email_notification: $("pref-email").value})});
    toast("Préférences enregistrées : elles s'appliquent dès le prochain audit.", "ok");
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- Fonctionnalités de l'énoncé : état en direct et tests réels sans LLM ---------- */
let cartesFonc = [];
const liste = (items) => items.length ? `<div class="puces">${items.map(x => `<span>${echap(x)}</span>`).join("")}</div>` : "—";
const ligneD = (g, d) => `<div class="ligne-d"><span>${g}</span><b>${d}</b></div>`;
const ETATS_FONC = {ok: ["ok", "✅ Fonctionnel"], "non configuré": ["nonconfig", "⚠️ Non configuré"], erreur: ["erreur", "❌ En erreur"]};

function rendreDonnees(c) {
  const d = c.donnees || {}, t = (c.dernier_test && c.dernier_test.details) || {};
  if (d.erreur) return `<span class="erreur">${echap(d.erreur)}</span>`;
  switch (c.id) {
    case "instructions":
      return ligneD("Fichier", `<code>${echap(d.fichier)}</code>`) + ligneD("Règles numérotées", d.nombre_regles) + ligneD("Taille transmise", d.caracteres + " caractères")
        + `<ol>${d.regles.map(r => `<li>${echap(r)}</li>`).join("")}</ol>`;
    case "skills":
      return d.declarees.map(s => `<div class="ligne-d"><span><code>${echap(s.nom)}</code><br><span class="note">${echap(s.description)}</span></span></div>`).join("")
        + (t.chargees ? `<div style="margin-top:6px">Chargées par Claude Code : ${liste(t.chargees)}</div>` : "");
    case "tools": {
      const tools = t.tools || d.tools.map(n => ({nom: n, description: ""}));
      return `<div class="note" style="margin-bottom:4px">${t.tools ? "Liste réelle (tools/list du dernier test)" : "Déclarés dans " + echap(d.serveur) + " (lancez le test pour le tools/list réel)"} : <b>${tools.length}</b></div>`
        + tools.map(x => `<div class="ligne-d"><code>${echap(x.nom)}</code><span class="note" style="text-align:right">${echap(x.description || "")}</span></div>`).join("");
    }
    case "connecteurs":
      return Object.entries(d).map(([nom, x]) => ligneD(`<b>${echap(NOMS_CONNECTEURS[nom] || nom)}</b><br><span class="note">${echap(x.dernier ? x.dernier.date + " — " + x.dernier.message : x.detail)}</span>`,
        `<span class="etat-fonc ${x.statut === "ok" ? "ok" : x.statut === "erreur" ? "erreur" : "nonconfig"}">${echap(x.statut)}</span>`)).join("");
    case "plugins":
      return d.plugins.map(p => `<div class="ligne-d"><span><b>${echap(p.nom)}</b> v${echap(p.version)}<br><span class="note">${echap(p.description)}</span></span></div>
        <div style="margin:4px 0 8px">Skills : ${liste(p.skills)} Serveurs MCP : ${liste(p.serveurs_mcp)}</div>`).join("")
        + (t.dependances ? `<div>OSV.dev (01_serveur_sain) : ${t.dependances.map(x => `${echap(x.paquet)} → ${x.vulnerabilites} vuln.`).join(" · ")}</div>` : "");
    case "mcp":
      return d.serveurs.map(s => {
        const vivant = (t.serveurs || []).find(x => x.nom === s.nom);
        return ligneD(`<code>${echap(s.nom)}</code><br><span class="note">${echap(s.transport)} · ${echap(s.fichier)}</span>`,
          vivant ? `<span class="etat-fonc ${vivant.statut === "connected" ? "ok" : "erreur"}">${echap(vivant.statut)} · ${vivant.tools} tools</span>` : "—");
      }).join("") + `<div class="note" style="margin-top:6px">Outils natifs : Skill uniquement · ${d.outils_autorises} tools en liste blanche · mode dontAsk</div>`;
    case "knowledge":
      return d.documents.map(x => ligneD(`<code>${echap(x.fichier)}</code><br><span class="note">${echap(x.titre)}</span>`, `${x.sections} sections`)).join("")
        + `<div class="saisie" style="margin-top:8px"><input id="q-knowledge" placeholder="Rechercher (ex. tool poisoning)" onkeydown="if(event.key==='Enter')rechercherKnowledge()">
           <button class="btn" onclick="rechercherKnowledge()">${icone("loupe", "width:15px;height:15px")}</button></div><div id="res-knowledge"></div>`;
    case "memoire":
      return `<b>Long terme (SQLite)</b>` + Object.entries(d.tables).map(([k, v]) => ligneD(`<code>${echap(k)}</code>`, `${v} ligne(s)`)).join("")
        + ligneD("Préférence : niveau de détail", echap(d.preferences.niveau_detail)) + ligneD("Préférence : adresse de notification", echap(d.preferences.email_notification))
        + `<div style="margin-top:6px"><b>Court terme : sessions récentes</b></div>` + (d.sessions.length ? d.sessions.map(s => ligneD(echap(s.titre.slice(0, 50)), `${s.messages} msg`)).join("") : "—");
    case "authentification":
      return d.mecanismes.map(m => ligneD(`<b>${echap(m.nom)}</b><br><span class="note">${echap(m.type)} · ${echap(m.stockage)}${m.portee ? " · " + echap(m.portee) : ""}</span>`, echap(m.etat))).join("")
        + (t.verifications ? `<div style="margin-top:6px">${Object.entries(t.verifications).map(([k, v]) => `${v ? "✅" : "❌"} ${echap(k)}`).join("<br>")}</div>` : "");
    case "bonus":
      return ligneD("Déclencheur", `<code>${echap(d.declencheur)}</code>`) + ligneD("Prochaine exécution", echap(d.prochaine_execution)) + ligneD("Exécutions", d.executions) + ligneD("Serveurs surveillés", d.serveurs_surveilles);
  }
  return "";
}

function rendreCarte(c) {
  const t = c.dernier_test;
  const [classe, libelle] = t ? (ETATS_FONC[t.statut] || ETATS_FONC.erreur) : ["attente", "Non testé"];
  return `<div class="carte fonc" id="fonc-${c.id}">
    <div class="fonc-tete"><span class="num">${c.numero || "★"}</span><h3>${echap(c.nom)}</h3><span class="etat-fonc ${classe}">${libelle}</span></div>
    <div class="definition">Énoncé : « ${echap(c.definition)} »</div>
    <p class="justification">${echap(c.justification)}</p>
    <div class="donnees-fonc">${rendreDonnees(c)}</div>
    <div class="fonc-pied"><div class="resultat ${t ? (t.ok ? "ok" : "erreur") : ""}">${t ? `${echap(t.date)} · ${echap(t.message)}${t.duree_s != null ? ` (${t.duree_s} s)` : ""}` : "Cliquez sur Tester pour un test réel."}</div>
      <button class="btn" onclick="testerFonc('${c.id}')">${icone("play", "width:15px;height:15px")}Tester</button></div></div>`;
}

function majCompteurFonc() {
  const n = cartesFonc.filter(c => c.numero && c.dernier_test && c.dernier_test.ok).length;
  $("compteur-fonc").textContent = `${n}/9`; $("barre-fonc").style.width = (n / 9 * 100) + "%";
  $("nb-fonc").textContent = `${n}/9`; $("nb-fonc").classList.toggle("cache", !cartesFonc.length);
}
async function chargerFonctionnalites() {
  if (!cartesFonc.length) $("grille-fonc").innerHTML = `<div class="attente"><div class="spinner"></div>Chargement…</div>`;
  try { cartesFonc = await api("/api/fonctionnalites"); } catch (e) { toast(e.message, "err"); return; }
  $("grille-fonc").innerHTML = cartesFonc.map(rendreCarte).join("");
  majCompteurFonc();
}
async function testerFonc(id, silencieux = false) {
  const carte = cartesFonc.find(c => c.id === id), el = $("fonc-" + id);
  if (el) { el.querySelector(".resultat").innerHTML = `<span class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:middle"></span> Test en cours…`; el.querySelector(".fonc-pied .btn").disabled = true; }
  let r;
  try { r = await post(`/api/fonctionnalites/${id}/tester`); } catch (e) { r = {ok: false, statut: "erreur", message: e.message}; }
  carte.dernier_test = r;
  try { const maj = await api("/api/fonctionnalites"); const c2 = maj.find(c => c.id === id); if (c2) { carte.donnees = c2.donnees; carte.dernier_test = {...c2.dernier_test, details: r.details || c2.dernier_test?.details}; } } catch {}
  if ($("fonc-" + id)) $("fonc-" + id).outerHTML = rendreCarte(carte);
  majCompteurFonc();
  if (!silencieux) toast(`${carte.nom} : ${r.message}`, r.ok ? "ok" : "err");
  if (id === "connecteurs") chargerConnecteurs();
  return r;
}
async function toutTesterFonc() {
  $("btn-tout-tester").disabled = true;
  if (!cartesFonc.length) await chargerFonctionnalites();
  for (const [i, c] of cartesFonc.entries()) {
    $("info-fonc").textContent = `Test ${i + 1}/${cartesFonc.length} : ${c.nom}…`;
    await testerFonc(c.id, true);
  }
  const n = cartesFonc.filter(c => c.numero && c.dernier_test?.ok).length;
  $("info-fonc").textContent = `Terminé : ${n}/9 fonctionnalités opérationnelles (+ bonus ${cartesFonc.find(c => c.id === "bonus")?.dernier_test?.ok ? "✅" : "❌"}). Aucun quota Claude consommé.`;
  toast(`${n}/9 fonctionnalités opérationnelles`, n === 9 ? "ok" : "err");
  $("btn-tout-tester").disabled = false;
}
async function rechercherKnowledge() {
  const q = $("q-knowledge").value.trim(); if (!q) return;
  try {
    const r = await api("/api/knowledge?q=" + encodeURIComponent(q));
    $("res-knowledge").innerHTML = r.length ? r.map(x => `<div class="ligne-d"><span><b>${echap(x.titre)}</b><br><span class="note">${echap(x.source)} — ${echap(x.texte.replace(/^#+.*\n/, "").slice(0, 180))}…</span></span><b>${x.pertinence}</b></div>`).join("")
      : `<div class="note">Aucun passage pertinent.</div>`;
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- Historique, approuvés, planification ---------- */
const couleurVerdict = v => ({INSTALLER:"--ok", CORRIGER:"--eleve", REJETER:"--crit"}[v] || "--doux");
const vide = (ic, titre, texte) => `<div class="vide"><div class="illus">${icone(ic)}</div><h3>${titre}</h3><div>${texte}</div></div>`;

async function chargerHistorique() {
  const l = await api("/api/audits");
  const celluleDrive = a => {
    const lien = lienDriveSur(a.drive_lien);
    if (lien) return `<a class="btn" style="padding:5px 10px" href="${echap(lien)}" target="_blank" rel="noopener noreferrer">${icone("drive", "width:15px;height:15px")}Drive</a>`;
    return `<span class="note" title="${echap(a.drive_statut || "")}">${echap((a.drive_statut || "—").split(" :")[0])}</span>`;
  };
  const celluleMail = a => {
    const s = (a.email_statut || "—").split(" :")[0];
    return `<span class="badge ${s === "ok" ? "ok" : s === "erreur" ? "critique" : "faible"}" title="${echap(a.email_statut || "")}">${echap(s === "ok" ? "envoyé" : s)}</span>`;
  };
  $("historique").innerHTML = l.length ? `<div class="tableau"><table><thead><tr><th>N°</th><th>Date</th><th>Cible</th><th>Type</th><th>Score</th><th>Verdict</th><th>Rapport Drive</th><th>E-mail</th><th></th></tr></thead><tbody>` +
    l.map(a => `<tr><td>${a.id}</td><td>${echap(a.date)}</td><td><b>${echap(a.cible)}</b></td><td>${echap((a.type || "").replace("_", " "))}</td>
      <td>${a.score}<span class="mini-barre"><i style="width:${Math.min(100, a.score)}%;background:var(${couleurVerdict(a.verdict)})"></i></span></td>
      <td><span class="verdict v-${a.verdict}" style="font-size:11.5px;padding:3px 9px">${a.verdict}</span></td>
      <td>${celluleDrive(a)}</td><td>${celluleMail(a)}</td>
      <td><a class="btn" style="padding:5px 10px" href="/api/audits/${a.id}/rapport.md">${icone("dl", "width:15px;height:15px")}Rapport</a></td></tr>`).join("") + "</tbody></table></div>"
    : vide("histo", "Aucun audit", "Les audits lancés depuis la vue Audit apparaîtront ici.");
}
async function chargerApprouves() {
  const l = await api("/api/approuves");
  $("approuves").innerHTML = l.length ? `<div class="tableau"><table><thead><tr><th>Nom</th><th>Copie installée</th><th>Approuvé le</th><th>Statut</th><th>Dernière vérification</th><th>Démonstration</th></tr></thead><tbody>` +
    l.map(s => `<tr><td><b>${echap(s.nom)}</b></td><td><code>${echap(s.chemin)}</code></td><td>${echap(s.date_approbation)}</td>
    <td><span class="badge ${s.statut === "approuvé" ? "ok" : "critique"}">${icone(s.statut === "approuvé" ? "check" : "alerte", "width:12px;height:12px")}${echap(s.statut)}</span></td><td>${echap(s.derniere_verification)}</td>
    <td><button class="btn danger" style="padding:6px 11px" onclick="simulerMiseAJour('${echap(s.nom)}')">${icone("alerte", "width:15px;height:15px")}Simuler une mise à jour malveillante</button></td></tr>`).join("") + "</tbody></table></div>"
    : vide("serveur", "Aucun serveur approuvé", "Auditez un serveur sain (verdict INSTALLER) puis cliquez sur « Approuver et installer ».");
}
async function simulerMiseAJour(nom) {
  const ok = await demander({titre:"Simuler une mise à jour malveillante", texte:`Remplacer silencieusement le serveur installé « ${nom} » par une version modifiée (scénario rug pull) ?`, confirmer:"Simuler", danger:true});
  if (!ok) return;
  try { const r = await post("/api/demo/mise-a-jour-malveillante", {nom}); toast(r.info); chargerApprouves(); }
  catch (e) { toast(e.message, "err"); }
}
async function chargerPlanif() {
  const p = await api("/api/planification");
  $("planif").innerHTML = `
    <div class="tuile"><div class="lib">${icone("horloge", "width:15px;height:15px")}Déclencheur</div><div class="val"><code>${echap(p.declencheur)}</code></div></div>
    <div class="tuile"><div class="lib">${icone("play", "width:15px;height:15px")}Prochaine exécution</div><div class="val">${echap((p.prochaine_execution || "-").replace(/\.\d+/, ""))}</div></div>`;
  const a = await api("/api/alertes");
  majCompteurAlertes(a);
  $("alertes").innerHTML = a.length ? a.map(x => `<div class="alerte"><div class="ic-alerte">${icone("alerte", "width:17px;height:17px")}</div><div>
      <div class="entete-alerte"><b>${echap(x.cible)}</b><span class="badge critique">${echap(x.type)}</span><span class="note">${echap(x.date)}</span></div>
      <pre>${echap(x.message)}</pre></div></div>`).join("")
    : vide("check", "Aucune alerte", "Les rug pulls détectés et les alertes envoyées apparaîtront ici.");
}
async function majCompteurAlertes(liste) {
  try {
    const a = liste || await api("/api/alertes");
    $("nb-alertes").textContent = a.length; $("nb-alertes").classList.toggle("cache", !a.length);
  } catch {}
}
async function executerReaudit() {
  try {
    const r = await post("/api/planification/executer");
    $("bilan").textContent = `${r.verifies} serveur(s) vérifié(s) — ${r.rug_pulls.length} rug pull(s) détecté(s).`;
    toast($("bilan").textContent, r.rug_pulls.length ? "err" : "ok");
    chargerPlanif();
  } catch (e) { toast(e.message, "err"); }
}

demarrer();
