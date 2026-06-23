# Abuser d'une IA comme C2 — Cloud-Sourced C2

---
title: "Abuse AI as C2 : Analyse et Remédiation"
date: 2026-06-23
keywords: ["abused-ai-c2", "blue-team", "steganography"]
layout: post
---

> Comment un malware peut utiliser une API d'IA légitime (OpenAI, Anthropic…) comme canal de commande et contrôle, et comment le détecter.

---

## Le principe

Un C2 classique nécessite un serveur malveillant hébergé quelque part — facilement bloqué par réputation de domaine.

L'idée ici est différente : **utiliser une API d'IA légitime comme relais de commandes**. Le trafic sort vers `api.openai.com`, un domaine souvent en whitelist. Les défenses réseau ne voient rien d'anormal.

Le flux ressemble à ça :

```
Attaquant → écrit des "messages" sur son compte IA
Malware   → interroge l'API (call-home régulier)
Réponse   → contient les ordres cachés dans du texte anodin
Malware   → décode et exécute
```

Les ordres sont transmis via du texte en langage courant. C'est de la **stéganographie linguistique** — les équipes de défense, sans contexte, n'y voient qu'une conversation banale.

---

## Deux techniques d'encodage courantes

### A — Mapping par mots-clés

On définit un dictionnaire de correspondance mot ↔ commande. Le malware extrait les mots-clés du texte reçu.

```python
COMMAND_MAPPING = {
    "maintenance": "internal_recon",
    "archivage":   "data_exfiltration",
    "clôture":     "terminate_process"
}
```

La réponse de l'IA pourrait ressembler à :

> *"Je dois faire la maintenance de ma maison, consulter les archives et poser une clôture."*

Trois mots-clés → trois commandes déclenchées.

---

### B — Balise encodée dans le texte

Le texte est anodin, mais contient un bloc délimité (entre crochets, caractères spéciaux…) encodé en Base64 ou chiffré.

```python
import re, base64

api_response = (
    "Bonjour, la mise à jour est disponible. "
    "Bloc de validation : [Y21kLmV4ZSBfXyB0YXNrbGlzdA==]. "
    "Bonne journée."
)

def decode_payload(text):
    match = re.search(r'\[(.*?)\]', text)
    if match:
        return base64.b64decode(match.group(1)).decode('utf-8')
    return None

command = decode_payload(api_response)
# → "cmd.exe __ tasklist"
```

La regex cible le blob, le décode, et le malware exécute la commande obtenue.

---

## Pourquoi c'est efficace

- Pas besoin d'infrastructure C2 dédiée — l'attaquant utilise un compte IA standard
- Le domaine cible est légitime et souvent en whitelist
- Le contenu chiffré ou encodé est indiscernable d'une réponse normale
- Aucune signature réseau connue à détecter

---

## Remédiation

La détection par réputation de domaine est inutile ici. Il faut se concentrer sur le **comportement**.

### Réseau

- **Inspection SSL/TLS obligatoire** sur les flux vers les catégories "IA" et "Cloud" — sans ça, le trafic reste une boîte noire.
- **Bloquer `api.openai.com` / `api.anthropic.com`** pour l'ensemble du parc, sauf les serveurs de dev identifiés. Les utilisateurs finaux n'ont besoin que de l'interface web, pas de l'API.
- **Passerelle API centralisée** : toutes les requêtes IA des développeurs transitent par un proxy interne qui journalise les volumes et patterns.

### Endpoint (EDR)

- **Alerter si** un binaire non signé, `powershell.exe`, `cmd.exe` ou `wscript.exe` initie une connexion vers les plages IP d'OpenAI ou Azure. Seuls les navigateurs légitimes devraient faire ces appels depuis les postes.
- **Surveiller les instances headless** (WebView2, navigateurs sans interface) lancées par des processus tiers — technique fréquente pour simuler une activité humaine sur une interface IA.

### SIEM / Threat Hunting

- **Détection de beaconing** : un humain interagit par vagues irrégulières. Un malware appelle l'API à intervalles fixes (ex. toutes les 30 secondes). Une requête SIEM sur la régularité des connexions peut le trahir.
- **Surveillance de l'entropie** : un volume anormalement élevé de requêtes POST depuis un poste (exfiltration cachée dans les prompts) ou des connexions persistantes vers une API LLM doivent déclencher une alerte.

### Secrets & Identité

- **Scanner les dépôts et postes** pour des clés API en clair (chaînes `sk-`, tokens Azure…). Des outils comme GitGuardian automatisent ça.
- **Alertes de surcoût** sur les consoles cloud : une clé compromise réutilisée comme relais C2 génère un pic d'utilisation détectable — configurer une révocation automatique en cas d'anomalie.

---

## En résumé

| Aspect | C2 classique | Cloud-Sourced C2 |
|---|---|---|
| Infrastructure | Serveur malveillant | Compte IA légitime |
| Détection réseau | Possible (réputation) | Très difficile |
| Compétences requises | Élevées (infra réseau) | Faibles (API + prompts) |
| Défense efficace | Blocage de domaine | Analyse comportementale |

La technique transforme un outil de productivité en relais C2 involontaire. La réponse défensive doit se déplacer du périmètre vers l'**analyse comportementale** des endpoints et des flux.

---

## Ressources

- [MITRE ATT&CK — C2 via Web Service (T1102)](https://attack.mitre.org/techniques/T1102/)
- [HackTricks — C2 Infrastructure](https://book.hacktricks.xyz/)
- [OpenAI — Security best practices](https://platform.openai.com/docs/guides/safety-best-practices)
