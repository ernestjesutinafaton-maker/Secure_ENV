# Env Guard

Env Guard est un vérificateur local en Python qui aide à repérer, avant un
commit :

- les variables d'environnement utilisées dans le code mais oubliées dans
  `.env.example` ;
- les mots de passe, jetons et clés API écrits en dur dans le code ;
- les fichiers `.env` suivis par Git ou absents du `.gitignore`.

Il n'envoie aucun contenu à un service externe et n'affiche jamais la valeur
d'un secret détecté : seulement le fichier et la ligne.

## Installation

Python 3.10 ou plus récent et Git sont requis. Aucune dépendance externe.

Pour que la vérification se lance automatiquement à chaque `git commit`,
depuis le dépôt à protéger :

```powershell
python chemin\vers\env_guard.py --install-hook
```

Le commit est alors bloqué si un problème est détecté. Si un hook `pre-commit`
existe déjà, Env Guard refuse de l'écraser ; ajoutez `--force` pour le
remplacer.

## Utilisation manuelle

```powershell
python .\env_guard.py          # lignes ajoutées dans les changements indexés
python .\env_guard.py --all    # tous les fichiers suivis et non ignorés
```

Le code de sortie vaut `0` si aucun problème n'est détecté, `1` si des problèmes
sont signalés et `2` en cas d'erreur d'exécution ou de configuration.

Exemple de sortie :

```text
Env Guard : vérification échouée (2 problème(s))

ERREUR  Secret potentiel détecté : valeur affectée à une variable sensible.
        settings.py:12
ERREUR  Variable STRIPE_KEY absente de .env.example.
        app/payment.py:4
```

## Contrôles

**Variables manquantes.** Les usages `os.getenv`, `os.environ`, `process.env`
et `import.meta.env` (Python, JavaScript, TypeScript) sont comparés aux noms
déclarés dans `.env.example`.

**Secrets en dur.**

- Formats connus : clés privées, clés AWS, jetons GitHub, Slack, clés Stripe,
  Google, OpenAI, Anthropic, et URL contenant un mot de passe
  (`postgres://user:<mot-de-passe>@hôte`).
- Affectations à un nom sensible (`password`, `secret`, `token`, `api_key`…),
  y compris avec préfixe ou suffixe : `DB_PASSWORD`, `SECRET_KEY`, `apiKey`,
  `"api_key": "..."`.
- Dans le code, seules les chaînes littérales comptent : affecter à
  `password` une expression comme `request.form["password"]`, ou écrire la
  comparaison `password == "x"`, n'est pas signalé. Dans les fichiers de configuration (`.env`, YAML, INI…), la valeur
  brute est examinée.
- Les valeurs fictives sont acceptées : vide, `changeme`, `<votre-clé>`,
  `your_token`, `xxxx`, `${VARIABLE}`, `os.getenv(...)`.

**Fichiers `.env`.** Un fichier `.env` ou `.env.*` suivi par Git, ou présent
sans être ignoré, est signalé. `.env.example`, `.env.sample`, `.env.template`
et `.env.dist` sont autorisés par défaut.

La détection repose sur des motifs : elle peut produire des faux positifs ou
manquer des secrets. Elle ne remplace ni une revue de code ni la rotation d'un
secret déjà exposé. **Un secret qui a été commité ou poussé doit être considéré
comme compromis et révoqué**, même après sa suppression du code.

## Configuration

Le fichier `.env-guard.json`, à la racine du dépôt, peut contenir :

```json
{
  "ignore_paths": ["vendor/**"],
  "allowed_env_files": [".env.development.example"],
  "secret_allowlist": [
    {
      "path": "tests/fixtures/*.py",
      "pattern": "EXAMPLE_TOKEN",
      "reason": "Valeur fictive dans un test"
    }
  ]
}
```

- `ignore_paths` : fichiers exclus de toutes les vérifications.
- `allowed_env_files` : fichiers `.env.*` autorisés dans le dépôt.
- `secret_allowlist` : exceptions ciblées. Une ligne n'est ignorée que si elle
  correspond à la fois au chemin et à l'expression régulière ; `reason` est
  obligatoire pour garder une trace de la justification.

Ce dépôt exclut `tests/test_env_guard.py`, qui contient volontairement de faux
secrets servant de données de test.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Limites

- L'analyse des variables couvre Python et JavaScript / TypeScript pour les
  syntaxes courantes (pas la déstructuration `const { X } = process.env`).
- Le mode par défaut vérifie les lignes ajoutées, pas l'historique Git.
- Le hook peut être contourné avec `git commit --no-verify`.
- Le hook enregistre le chemin absolu de Python et du script : relancez
  `--install-hook` si vous déplacez l'un des deux.
