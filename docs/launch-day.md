# Launch day — Product Hunt (20 oct., 09:01 FR)

> Objectif : concentrer tout le trafic le même jour pour maximiser
> la vélocité d'étoiles GitHub (c'est ce qui déclenche le Trending).
> Publier entre 09h et 10h, juste après le passage en homepage PH.

## 📊 État global — tout ce qui est fait

| Canal | Statut | Lien / note |
|---|---|---|
| Show HN #1 | ✅ posté, coulé (score 1) | repost autorisé — nouvel angle « histoire » dans drafts-launch.md |
| GitHub Discussions | ✅ activées + #39 épinglée | « What did you catch? » bilingue |
| Topics | ✅ 20/20 + `hacktoberfest` | `pinokio` retiré |
| FUNDING.yml | ✅ commit `fbb06b6` | prêt pour GitHub Sponsors |
| Social preview | ✅ image anonymisée uploadée | ancien fichier contenait vrais noms d'appareils — remplacé |
| Badges Shields | ✅ cache empoisonné corrigé | flat/flat-square = nouvelles clés cache |
| README zh-CN | ✅ en ligne | ~55 visiteurs chinois/jour |
| Star-history badge | ✅ dans README | |
| Presse EN | ✅ soumis | OMG Ubuntu, 9to5Linux, It's FOSS (mail), Linuxiac (mail) |
| Presse FR | ✅ soumis | Korben ×2 (contact@aixis.fr puis berthomiereadam@gmail.com) |
| Directories | ✅ | SaaSHub (live), StackShare (live #233 Monitoring), AlternativeTo (modération), daily.dev squad (review) |
| Dev.to | ✅ 5 articles | canonical unique → fichier source GitHub |
| Medium | ✅ article fondateur | canonical → dev.to conservé |
| Qiita 🇯🇵 | ✅ article publié | qiita.com/aixis/items/f7686017adaa0b8be861 |
| Chine 🇨🇳 | ⚠️ | HelloGitHub #4028 ✅ ; V2EX/linux.do = invitation ; Juejin = tél. chinois |
| GHCR | ✅ `ghcr.io/aixisstudio/snitch` publique | CI auto aux tags |
| winget | ✅ PR #455520 + CLA signée | en validation Microsoft |
| awesome-privacy | ❌ PR fermée (règle 16 semaines) | resoumission ~20 janv. 2026 |
| Payant/mort — exclus | — | BetaList ($99+), OpenAlternative ($97+), Slant (SSL mort), Lobsters (invitation), Fazier (badge+3 comments), Microlaunch (Pro payant) |
| Vague 4 — directories | ✅ | LibHunt live, DevHunt listing gratuit (upsell payant skip) |
| Vague 4 — éditorial | ⏳ en attente | Console.dev (pitch envoyé), LinuxFR (modération), Journal du hacker (invitation demandée) |
| Zenn 🇯🇵 | ✅ article publié | zenn.dev/aixisstudio/articles/1b0a285e1bc8a5 |
| IndieHackers | ✅ page produit live | indiehackers.com/product/snitch — 11 tags, motivation, France |
| Homebrew | ⚠️ tap perso OK, upstream bloqué | `brew install --cask aixisstudio/tap/snitch` fonctionne (repo homebrew-tap, cask v1.0.5, postflight enlève la quarantaine) ; upstream homebrew-cask bloqué : conflit token `snitch` + app ad-hoc signée |
| Réseau perso | n/a | aucun — toute la campagne est 100% canaux publics |

---

## 1. Post X — FR

```
🔴 Snitch est live sur Product Hunt !

Votre ordinateur fait des centaines de connexions cachées par heure.
Snitch les montre toutes : graphe temps réel + carte du monde, géoloc offline, attribution par app, zéro télémétrie.

⭐ Si ça vous aide, une étoile sur GitHub compte beaucoup :
github.com/aixisstudio/Snitch

#opensource #privacy
```

## 2. Post X — EN

```
🔴 Snitch is live on Product Hunt!

Your computer makes hundreds of hidden connections every hour. Snitch shows them all — real-time node graph + world map, offline geolocation, per-app attribution, zero telemetry.

⭐ If it's useful, a star on GitHub means a lot:
github.com/aixisstudio/Snitch

#opensource #privacy #cybersecurity
```

## 3. Post LinkedIn — EN (page aiXis + repartage profil)

```
🔴 Snitch is live on Product Hunt today!

Your computer makes hundreds of silent connections every hour — and most tools either cost money (Little Snitch) or require a networking degree (Wireshark).

Snitch shows every connection in real time:
• Animated node graph + world map
• Per-process attribution
• 100% offline geolocation — zero telemetry
• Free, open-source (AGPL), EN/FR, demo mode without root

Try it, and if it's useful, a ⭐ on GitHub helps a lot:
github.com/aixisstudio/Snitch

#opensource #privacy #cybersecurity #linux
```

## 4. Update Reddit r/opensource (commentaire sur ton post existant)

```
Update: Snitch is now live on Product Hunt — link in comments. If the project is useful to you, a GitHub star helps visibility a lot. Thanks for all the feedback so far!
```

## 5. Communautés à poster (légitimes, pas du spam)

| Communauté | Où | Angle |
|---|---|---|
| **PrivacyGuides forum** | discuss.privacyguides.net | Outil de visualisation réseau local-first, aligné avec leurs valeurs — poster dans la catégorie "Tools" en présentant le projet honnêtement |
| **r/selfhosted** | reddit.com/r/selfhosted | Snitch tourne en Docker, self-hosted — post autorisé mais vérifie leurs règles self-promo (souvent OK avec le flair adéquat) |
| **Self-Hosted podcast Discord** | discord.selfhosted.show | Canal #show-and-tell / #homelab — partage naturel, la communauté adore les outils réseau |
| **lobste.rs** | lobste.rs | Compte sur invitation — si tu connais quelqu'un dedans, très haute qualité de trafic dev |
| **Mastodon/Bluesky** | hashtags #opensource #privacy #foss | Si tu as des comptes, même texte que X — l'audience FLOSS y est très active |

## ⚠️ Rappels

- Pas d'achat d'étoiles ni de groupes d'upvotes — GitHub et PH bannissent
- Sur PH demain : réponds vite aux commentaires dans le Launch Day dashboard — l'engagement booste le classement
- Lien GitHub direct partout (pas la vitrine) pour le clic étoile

## Vague 2 — leçons apprises (18 oct)

| Canal | Résultat | Leçon |
|---|---|---|
| daily.dev | ✅ compte créé + post soumis (review admin, squad « Open Source » 15,8K) | Posts possibles uniquement via squads ; sélecteur d'audience fragile — cliquer via coords réelles `getBoundingClientRect` + CGEvent ; le bouton « Leave » est DANS l'item de squad (attention) |
| Stackshare | ✅ page LIVE stackshare.io/snitch | Signup = OAuth GitHub/Google only ; « List a Tool » accepte URL GitHub ; logo carré requis (upload via DataTransfer+base64) ; features séparées par `;` |
| BetaList | ❌ abandonné | Payant uniquement (99-299$) — pas de tier gratuit |
| Slant | ❌ mort | SSL 526 — site abandonné, ne plus le cibler |
| Korben | ✅ re-soumis (form « Présenter un outil ») | Turnstile auto-résout ; formulaire se vide après envoi = confirmation |
| linux.do | ❌ invitation | Sur invitation seulement — idem V2EX |
| Juejin | ❌ bloqué | Inscription par téléphone chinois |
| Winget | ✅ CLA signée | Commentaire `agree` posté sur PR #455520 |

## Canaux chinois — état final

- **V2EX** : invitation requise → bloqué
- **linux.do** : invitation requise → bloqué
- **Juejin** : téléphone chinois requis → bloqué
- **HelloGitHub #4028** : ✅ issue créée (canal officiel de soumission)
- Posts prêts dans `~/Downloads/chinese-posts.md` si un contact a des comptes

## Vague 3 — contenu & plateformes internationales

| Canal | Résultat | Leçon |
|---|---|---|
| dev.to ×5 | ✅ 5 articles publiés (canonical unique → fichier source GitHub) | `canonical_url` doit être unique par article — sinon « has already been taken » |
| Medium | ✅ article fondateur publié | Import via URL (canonical auto) ; signup = magic link email ; bypass paywall via option gratuite |
| Qiita | ✅ article japonais publié qiita.com/aixis/items/f7686017adaa0b8be861 | Vérif email obligatoire avant de poster (récupérer le lien dans Gmail puis /drafts/new) ; éditeur = CodeMirror (`.cm-content`) → paste via Cmd+V réel ; checkbox ToS+privacy à cocher dans le dialog de publication |

## Vague 4 — directories, éditorial & lancements

| Canal | Résultat | Leçon |
|---|---|---|
| LibHunt | ✅ **live** — libhunt.com/r/aixisstudio/Snitch | Soumission sans compte ; listing auto-créé puis métadonnées self-hosted activées via page d'édition (repo/3893635) |
| DevHunt | ✅ listing gratuit créé (slug snitch) | OAuth GitHub obligatoire ; métadonnées importées à corriger (nom « GitHub » → Snitch) ; catégorie Monitoring + pricing Free ; **upsell paid launch après création → skip**, le listing reste |
| Console.dev | ✅ pitch envoyé (hello@console.dev, sujet « Tool suggestion: Snitch… ») | Newsletter éditoriale — réponse non garantie ; corps via clic réel + frappe directe (paste KO dans Gmail) |
| LinuxFR | ✅ dépêche soumise à la modération | Formulaire sans compte ; champs `news[links][n][lang]` obligatoires (en pour GitHub, fr pour Pages) ; honeypot `news[pot_de_miel]` laissé vide ; preview « 0 erreurs » avant envoi |
| Journal du hacker | ✅ demande d'invitation envoyée | Invitation requise pour poster ; confirmation = mail à suivre |
| Zenn | ✅ article japonais publié — zenn.dev/aixisstudio/articles/1b0a285e1bc8a5 | Login Google → choisir berthomiereadam ; éditeur exige paste Cmd+V réel ; **autosave local** : dialog « 自動保存を復元する » au reload ; publication bloquée sans topics+catégorie (panneau 公開設定) ; dialog final « 公開する » |
| Fazier | ❌ abandonné | Tier free exige badge embed sur le site + 3 commentaires « helpful » sur d'autres produits + DR>0 — stoppé par l'utilisateur |
| Microlaunch | ❌ abandonné | Dialog « Pick your Launch » ne propose que Pro (payant, ~$29-49, -50% OSS) ; `/submit` redirige ; pas de tier gratuit effectif |
| IndieHackers | ✅ page produit **live** — indiehackers.com/product/snitch | Signup = Google OAuth (popup bloqué → hijack `window.open` → rediriger in-tab, Firebase auth handler) ; tagline ≤60 car. ; motivation ≤220 car. ; logo via input[type=file] + DataTransfer ; tags = `input[name=tagIds]` → setter `checked` + `change` (le `.click()` natif ne prend pas) ; les tags se décochtent si un save échoue — recocher juste avant le save final ; checkbox `published` = visibilité directory |
| Homebrew upstream | ❌ bloqué, documenté | Formula `snitch` existe déjà (karol-broda/snitch — inspecteur de connexions réseau, même domaine) → token refusé ou renommé type `snitch-app` ; **+ Snitch.app est ad-hoc signé, non notarizé** → Gatekeeper « damaged » sous quarantaine, maintien probable rejet ; à réévaluer si signature Developer ID un jour. **MAIS** : le tap perso `aixisstudio/homebrew-tap` existe déjà et fonctionne — `brew install --cask aixisstudio/tap/snitch` (postflight `xattr -dr quarantine`) ; la PRIORITÉ était déjà couverte |

### Notes techniques vague 4

- **LibHunt** : aucun compte requis, URL = `libhunt.com/submit` — le plus frictionless de tous les directories.
- **LinuxFR** : modération réelle, ton factuel obligatoire (pas de promo) — délai « heures ou jours ».
- **Zenn** : la page reloade parfois l'éditeur ; le contenu vit dans l'autosave local — restaurer via le dialog avant de réécrire.
- **Fazier/Microlaunch** : pattern émergent — les « launch platforms » gratuites ont migré vers des modèles payants ou gated (badge/engagement forcé). L'ère du « submit free » se réduit : restent LibHunt, DevHunt (listing), SaaSHub, StackShare.
- **Homebrew** : ne pas retenter sans (1) Developer ID + notarisation, (2) un token non conflictuel (`snitch-netmonitor` ?). Le formula karol-broda/snitch rend le conflit rédhibitoire même avec un token alternatif — confusion garantie en review.
