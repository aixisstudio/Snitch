# Snitch — Campagne growth vers GitHub Trending & 10K ⭐

> **Objectif : 100–300⭐ en 24h le jour J → entrée GitHub Trending → boucle auto-alimentée.**
> Règle d'or : tout le traffic doit converger le MÊME jour sur le repo GitHub.

---

## 🧠 La stratégie en 4 couches

```
Couche 4 — LONGUE TRAÎNE (semaines)   SEO articles, Q&A evergreen, directories
Couche 3 — BOUCLE DE RÉCURRENCE       chaque release = nouveau moment de partage
Couche 2 — JOUR J (mardi)             PH + HN repost + Reddit + social, tout empilé
Couche 1 — CONVERSION (toujours on)   repo qui convertit visiteur → star
```

---

## Couche 1 — Conversion du repo (fait / à vérifier)

- [x] Social preview custom anonymisée (og:image)
- [x] Discussions activées + welcome post épinglé
- [x] Topics optimisés (20/20, `hacktoberfest`, `little-snitch-alternative`)
- [x] FUNDING.yml
- [x] README trilingue (EN/FR/ZH) + GIF demo
- [ ] **CTA star subtil** en haut du README : ligne ajoutée ci-dessous
- [ ] Ajouter `awesome` badge + liens de téléchargement directs par OS dans les 10 premières lignes

---

## Couche 2 — Jour J : séquence de tir concentrée (mardi)

> Fenêtre unique. Chaque post doit dire « ⭐ on GitHub » explicitement.
> Le trending se joue sur la vélocité journalière.

| Heure Paris | Action | Où | Asset |
|---|---|---|---|
| 09h01 | Product Hunt live (00:01 PT) | PH | galerie + vidéo mp4 |
| 10h00 | Repost Show HN | HN | nouveau titre (story, pas feature) |
| 11h00 | Post X + vidéo | X | snitch-demo.mp4 |
| 11h30 | Post LinkedIn | LinkedIn | vidéo + texte FR/EN |
| 14h00 | Post r/selfhosted | Reddit Ezra_Hell | angle Docker/GHCR |
| 17h00 | Commentaires PH — répondre à CHAQUE commentaire | PH | boost classement |
| 20h00 | Post r/MacApps ou r/privacy si le premier accroche | Reddit | espacé, jamais 2 subs en rafale |
| 22h00 | Commentaire « day 1 recap » sur le post Reddit + thread X | social | momentum |

### Drafts prêts (fichier `docs/drafts-launch.md`)

Voir le fichier séparé — copiable-collable.

---

## Couche 3 — Récurrence : chaque release = une excuse de poster

- v1.1 (features utilisateurs des issues) → nouvelle vague posts dans 2-3 semaines
- Changelog structuré → cross-post dev.to/Medium
- « State of Snitch » post mensuel : métriques, ce qu'on a appris (HN adore la transparence chiffrée)

---

## Couche 4 — Longue traîne (le vrai moteur à 10K)

### 4.1 Articles SEO evergreen — dev.to + Medium + Hashnode (canonical → GitHub Pages)

Requêtes visées (volume réel, faible compétition) :

| Requête Google | Article à écrire |
|---|---|
| "little snitch alternative windows" | Snitch: a free open-source Little Snitch alternative for Windows |
| "little snitch alternative linux" | idem Linux/Docker |
| "glasswire alternative open source" | Snitch vs GlassWire: 100% local, no account |
| "see what my computer is connecting to" | How to see every connection your computer makes |
| "network monitor open source macos" | Why I built a privacy-first network monitor |

→ 5 articles, 1/semaine, angle honnête (ce que Snitch fait / ne fait PAS — pas de firewall).
Chaque article = backlink SEO + trafic récurrent pendant des années.

### 4.2 Q&A evergreen (indexés Google, trafic pendant des années)

Répondre sincèrement sur :
- Quora : "Is there a free alternative to Little Snitch?" (+variantes Windows/Linux)
- Super User / Ask Different : questions existantes sur le monitoring réseau
- Reddit : chercher les vieux threads "little snitch alternative" → commentaire utile

⚠️ Règle : la réponse doit être réellement utile (mentionner aussi Wireshark/tcpdump) — jamais un lien nu.

### 4.3 Directories restants (gratuits)

- [ ] openalternative.co — submit SaaS/tool
- [ ] fosshub.com — héberge les releases (miroir + SEO)
- [ ] SourceForge — listing OSS (vieux mais SEO puissant)
- [ ] alternativeto — ✅ fait (en modération)
- [ ] SaaSHub / Stackshare — ✅ faits

### 4.4 Agrégateurs X/Twitter à activer

Comptes qui republient des repos (DM ou reply public) :
- @tom_doerr — reposte des repos OSS à ~400K followers, il accepte les suggestions
- "Awesome open source" bots + agrégateurs trending
- Comptes FR : @korben (déjà soumis), @_kud, @m4d_z

### 4.5 Nouvelles langues = nouveaux marchés

- README.zh-CN ✅ (21% du trafic venait déjà de Chine)
- Prochaines cibles : **japonais** (Qiita = dev.to japonais, énorme audience OSS, signup email OK), **espagnol** (gros marché, peu d'outils traduits)
- Qiita article : traduire le post dev.to v1.0.5 en japonais → canal bleu océan

### 4.6 Forums de niche où Snitch a sa place

| Forum | Pourquoi |
|---|---|
| privacyguides.net/discuss | audience 100% alignée privacy, catégorie Tools |
| Self-Hosted Discord | canal #showcase — audience homelab qui adore les dashboards réseau |
| forum.autonomie.digital (FR) | communauté privacy FR active |
| ServeTheHome forums | réseau/pro — audience qui bidouille |
| Discords homelab (r/homelab Discord) | screenshots dashboards = engagement naturel |

### 4.7 Le différenciateur viral : le « catch »

Le contenu le plus viral possible pour Snitch = **des captures inattendues** (« mon imprimante parlait à un serveur en X »). Mécanique :
- Discussion « What did you catch? » déjà épinglée sur le repo
- Série X hebdo : 1 capture anonymisée/semaine (mode demo, marquée comme telle)
- Chaque release note inclut une capture sympa

### 4.8 Conférences & podcasts

- **FLOSS Weekly** (TWiT) — formulaire de suggestion public, adorent les outils privacy
- **Self-Hosted podcast** — ils ont un segment « community picks »
- **Linux Unplugged** — tip mail
- Conf CFP : FOSDEM (deadline ~décembre), PASS THE SALT (privacy), LeHack

---

## 🚫 Jamais (checklist éthique — ça détruirait le projet)

- Achat d'étoiles / groupes d'upvotes → ban GitHub + PH + mort de la réputation
- Bots/fake accounts → pattern détecté = shadowban du repo
- Spam de liens sans contexte
- Mentir sur les captures (démo = démo, marqué)

---

## 📏 Mesure

- Source de vérité : GitHub Insights → Traffic + Stars page
- Check trending : github.com/trending/python?since=daily — matin et soir le jour J
- Si trending atteint : screenshot → post X « we're trending » (effet boule de neige)
