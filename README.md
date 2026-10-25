# Emploi du temps — hébergement 100 % gratuit (≈ 10 minutes)

Serveur Node (Render, gratuit) + base PostgreSQL (Neon, gratuite et permanente).

## 1. Créer la base (Neon)
1. Va sur https://neon.com → crée un compte → « New project » (nom libre).
2. Sur le tableau de bord, clique **Connect** et copie l’adresse « Connection string »
   (elle commence par `postgresql://…`). Garde-la, c’est ta variable `DATABASE_URL`.

## 2. Mettre le code sur GitHub
1. Crée un dépôt vide sur https://github.com (bouton « New »).
2. Dézippe ce projet, puis dans le dépôt : « Add file » → « Upload files » → glisse **tout le contenu**
   du dossier (server.js, package.json, render.yaml, public/…). Valide (« Commit »).

## 3. Héberger sur Render
1. https://render.com → compte (connecte-toi avec GitHub) → **New +** → **Web Service** → choisis ton dépôt.
2. Réglages : Language `Node` · Build `npm install` · Start `npm start` · Instance type **Free**.
3. Dans « Environment Variables » ajoute :
   - `DATABASE_URL` = l’adresse copiée chez Neon
   - `NODE_ENV` = `production`
4. **Create Web Service**. Après 2–3 min, ouvre l’adresse `https://….onrender.com`, crée ton compte : c’est en ligne.

## À savoir
- Le service gratuit s’endort après 15 min d’inactivité : la première visite prend ~30–60 s, ensuite c’est rapide.
- Tes données sont dans Neon : elles ne sont jamais effacées quand le serveur dort ou redémarre.
- Test en local : `npm install` puis `DATABASE_URL="postgresql://…" node server.js` → http://localhost:3000
