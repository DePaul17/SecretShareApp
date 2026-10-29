# Coffre — partage de secrets à usage unique

## Installation
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
```

## Production
```bash
pip install gunicorn
COFFRE_BASE_URL=https://coffre.exemple.com gunicorn -w 2 -b 127.0.0.1:8000 app:app
```
Placez l'app derrière un proxy **HTTPS** (Caddy, nginx). Sans HTTPS, le secret transite en clair.

## Variables d'environnement
| Variable | Rôle | Défaut |
|---|---|---|
| `COFFRE_DB` | chemin de la base SQLite | `coffre.db` |
| `COFFRE_BASE_URL` | URL publique utilisée dans les liens | hôte de la requête |
| `PORT` | port en mode dev | `5000` |

## Modèle de sécurité
- Le code (8 caractères, 32 symboles ≈ 40 bits) n'est **jamais stocké** : il dérive la clé AES via scrypt. La base ne contient que le texte chiffré.
- 5 mauvais codes → destruction du secret (l'attaque par force brute en ligne devient impraticable).
- Lecture via POST uniquement : les aperçus de liens (Slack, Teams, mail) ne consomment pas le secret.
- Envoyez le lien et le code par **deux canaux différents**.
- Limite : un attaquant qui obtient la base *et* peut tester des codes hors ligne peut tenter de casser les 40 bits. Pour un secret très sensible, allongez le code (`range(8)` dans `generate_code`).
