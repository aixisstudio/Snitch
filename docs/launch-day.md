# Launch day — Product Hunt (20 oct., 09:01 FR)

> Objectif : concentrer tout le trafic le même jour pour maximiser
> la vélocité d'étoiles GitHub (c'est ce qui déclenche le Trending).
> Publier entre 09h et 10h, juste après le passage en homepage PH.

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
