# Recon

Inscription dans nano, de l'ip avec l'url.
```bash
$ sudo nano /etc/hosts
```

cyprusbank.thm


```bash
$ sudo nmap -sS -sC -sV 10.10.123.71

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-22 00:08 CET
Nmap scan report for cyprusbank.thm (10.10.123.71)
Host is up (0.031s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
|_  256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.10 seconds
```
# Fuzzing

```bash
$ ffuf -c -w /home/french/documents/seclists/discovery/web-content/directory-list-2.3-medium.txt:FUZZ -w http://cyprusbank.thm/FUZZ
```

Pour l'instant, il n'y que ce fichier qui est sorti.
```bash
index.html
```

J'ai essayé d'autres wordlists, toujours avec Ffuf mais ça ne donnait rien. Donc j'ai essayé avec GoBuster et les wordlists utilisés avec l'outil FFuf.

```bash
$ wfuzz -c --hw 3 -w /usr/share/seclists/Discovery/dns/subdomains-top1million-110000.txt -H "Host: FUZZ.cyprusbank.thm" cyprusbank.thm

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://cyprusbank.thm/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                            
=====================================================================

000000001:   200        8 L      24 W       252 Ch      "www"                                                                              
000000024:   302        0 L      4 W        28 Ch       "admin"                                                                            

Total time: 400.3569
Processed Requests: 114441
Filtered Requests: 114439
Requests/sec.: 285.8474
```

```bash
Ajout de l'extension au fichier /etc/hosts

$ sudo nano /etc/hosts
<adresse IP>	admin.cyprusbank.thm
```
 	
 	
Nous arrivons sur la page 'admin.cyprusbank.thm' et nous avons une page de connexion, les credentials fourni vont être utiles.
	
```bash
Olivia Cortez:olivi8
```
	
# Exploitation

Le site permet à un attaquant de manipuler les paramètres de l'URL. C'est à dire, qu'en changeant les valeurs depuis notre utilisateur, on peut accéder aux informations d'autres users. 
Ici, on peut par exemple automatiser le processus, en créant une liste de nombres qui se suivent, avec Python. 
Et utiliser Curl ou Burpsuite, afin de tester chaque paramètre de notre liste.

Dans cette machine, j'ai testé à la main, étant donné que ce n'est pas une cible du monde réelle, avec des milliers d'utilisateurs. C'est jouable.

```bash
http://admin.cyprusbank.thm/messages/?c=5


http://admin.cyprusbank.thm/messages/?c=10
```


```bash	
La page 10 contient la discussion suivante:
	
Banque nationale de Chypre - Chat administratif

ÉQUIPE DEV  : Merci Gayle, pouvez-vous partager vos informations d'identification ? Nous avons besoin d'un compte administrateur privilégié pour les tests

Gayle Bev : Bien sûr ! Mon mot de passe est 'p~]P@5!6;rs558:q'

ÉQUIPE DEV  : Très bien, nous essayons d'implémenter l'historique des discussions, tout devrait être prêt dans environ une semaine.

Gayle Bev : C'est agréable à entendre !

Gayle Bev : Les développeurs ont implémenté cette nouvelle fonctionnalité de messagerie que j'avais suggérée ! Qu'en pensez-vous ?

Greger Ivayla : Ça a l'air vraiment cool !

Jemmy Laurel : Hé, vous avez vu Mme Jacobs récemment ??

Olivia Cortez : Non, elle n'est plus là depuis un moment

Jemmy Laurel : Oh, est-ce qu'elle va bien ?
```


Nous arrivons sur le compte de Gayle Bev avec le password:
```bash
p~]P@5!6;rs558:q
```

Grâce à cela, nous voyons à la première page la réponse à la première question du CTF, le numéro de Tyrell Wellick
```bash	
Tyrell Wellick :	 	$20.855.900.000 	842-029-5701
```
