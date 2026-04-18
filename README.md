# Claude PWA — client mobile pour l'API Anthropic

Une **Progressive Web App** minimaliste pour discuter avec Claude depuis ton téléphone en utilisant ta propre clé API Anthropic.

- **Aucun backend, aucun build** — juste du HTML/CSS/JS pur.
- **Ta clé API est chiffrée** avec un code PIN (AES-GCM, dérivé via PBKDF2 600k itérations) et stockée uniquement dans le `localStorage` de ton navigateur.
- **Aucune donnée ne quitte ton téléphone** sauf les appels directs à `api.anthropic.com`.
- **Sécurité par défaut** : si l'API renvoie une erreur 401/403 (clé révoquée/invalide), l'app se verrouille immédiatement pour éviter toute facture imprévue.

## Fonctionnalités

- Chat avec streaming des réponses (texte en temps réel)
- Historique des conversations sauvegardé localement
- Support des images (Vision) — jusqu'à 5 MB par image
- Choix du modèle : Opus 4.7 (défaut), Sonnet 4.6, Haiku 4.5
- System prompt personnalisable
- Thème sombre
- Verrouillage par code PIN
- Installable comme une vraie app (Add to Home Screen)

## Déploiement sur GitHub Pages

### 1. Créer un repo GitHub

```bash
cd claude-pwa
git init
git add .
git commit -m "init"
git branch -M main
# Crée un repo vide sur github.com (par exemple: claude-pwa)
git remote add origin https://github.com/TON_USER/claude-pwa.git
git push -u origin main
```

### 2. Activer GitHub Pages

Sur GitHub → ton repo → **Settings → Pages** :
- **Source** : `GitHub Actions`

Le workflow `.github/workflows/deploy.yml` déploiera automatiquement à chaque push sur `main`.

### 3. Récupérer l'URL

Après quelques secondes, ton app est dispo sur :
```
https://TON_USER.github.io/claude-pwa/
```

> Note : GitHub Pages est **public** par défaut (tout le monde peut voir le code). C'est normal et safe — aucune clé n'est dans le code. Ta clé API reste sur ton téléphone uniquement.

### 4. Installer sur ton téléphone

**Android (Chrome)** :
1. Ouvre l'URL sur Chrome mobile.
2. Menu `⋮` → `Installer l'application` (ou `Ajouter à l'écran d'accueil`).
3. Confirme — l'app apparaît sur ton écran d'accueil.

**iOS (Safari)** :
1. Ouvre l'URL sur Safari.
2. Bouton partager → `Sur l'écran d'accueil`.
3. Confirme.

### 5. Premier lancement

1. Crée un code PIN (4 à 12 chiffres).
2. Colle ta clé API Anthropic (`sk-ant-...`).
3. C'est parti.

## Recommandations de sécurité

Avant d'utiliser cette app, sur [console.anthropic.com](https://console.anthropic.com) :

1. **Crée une clé API dédiée** pour le mobile (nomme-la `mobile-pwa`).
2. **Active une limite de dépense mensuelle** : *Settings → Limits → Monthly spend limit* (ex: 20 $).
3. **Active les alertes d'usage** (*Usage alerts*).
4. **Surveille** l'usage régulièrement les premiers jours.

Si la clé fuit (téléphone perdu, etc.), révoque-la en 1 clic — la limite de dépense te protège financièrement.

## Tester en local

Tu peux tester avant de déployer. Depuis le dossier `claude-pwa/` :

```bash
# Option 1 : Python
python -m http.server 8000

# Option 2 : Node (npx)
npx serve .

# Option 3 : n'importe quel serveur static
```

Puis ouvre `http://localhost:8000` dans ton navigateur.

> ⚠️ Pour tester depuis ton téléphone sur le même Wi-Fi, lance `ipconfig` (Windows) pour trouver l'IP de ton PC et ouvre `http://TON_IP:8000` sur le téléphone. Certaines fonctionnalités PWA (installation) nécessitent HTTPS — utilise GitHub Pages pour les tester vraiment.

## Architecture

```
claude-pwa/
├── index.html              # Structure HTML (écrans lock/apikey/app)
├── styles.css              # Thème sombre, responsive mobile
├── app.js                  # Toute la logique (ES modules, no build)
├── manifest.webmanifest    # PWA manifest
├── sw.js                   # Service worker (install, cache app shell)
├── assets/
│   └── icon.svg            # Icône de l'app
└── .github/workflows/deploy.yml  # Auto-deploy GitHub Pages
```

### Sécurité — détails techniques

- **PBKDF2** avec SHA-256, 600 000 itérations, sel aléatoire 16 bytes
- **AES-GCM 256 bits**, IV aléatoire 12 bytes
- Le PIN n'est **jamais** stocké — seul le blob chiffré est persisté
- Après déverrouillage, la clé en clair et le PIN restent **uniquement en mémoire** (variables JS), jamais écrits sur disque
- Un 401/403 de l'API déclenche un **verrou global** (`LS.LOCKED`) qui empêche tout nouvel appel jusqu'à changement de clé
- Le service worker **n'intercepte jamais** les requêtes vers `api.anthropic.com` — elles partent directement du navigateur

### Limitations

- La PWA utilise le header `anthropic-dangerous-direct-browser-access: true`, officiellement supporté par Anthropic mais nommé ainsi pour rappeler qu'en production côté organisation, un backend est préférable. Pour un usage **perso** avec une clé limitée, c'est acceptable.
- Les conversations sont stockées en clair dans `localStorage` (pas chiffrées). Si tu veux les protéger, utilise le PIN — sinon quelqu'un avec accès au téléphone pourrait lire l'historique via les DevTools.
- Pas de sync multi-appareils (voulu pour rester 100 % local).

## Mise à jour

Pour mettre à jour l'app après avoir modifié le code :

```bash
git add .
git commit -m "update"
git push
```

GitHub Actions redéploie automatiquement. Sur le téléphone, le service worker récupèrera la nouvelle version au prochain chargement (ou force-refresh dans Chrome).

## Licence

Fais-en ce que tu veux.
