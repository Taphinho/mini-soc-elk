# IR-001 — Détection d’un shell root via sudo

## 1. Synthèse

Le 3 novembre 2026, un test autorisé a été réalisé sur le laboratoire
Mini-SOC afin de vérifier la détection d’un shell lancé avec root
comme utilisateur cible via sudo.

L’événement a été collecté depuis journald par Filebeat, enrichi dans
Elasticsearch, puis détecté par une règle personnalisée Elastic Security.

L’alerte a été examinée et clôturée avec le motif `benign_positive`.
Un test négatif a ensuite confirmé qu’une commande sudo ordinaire était
collectée sans déclencher cette règle.

| Élément | Valeur |
|---|---|
| Référence | IR-001 |
| Classification | Test autorisé du laboratoire |
| Date du test positif | 2026-11-03 |
| Hôte | `white-hat` |
| Utilisateur source | `taphinho` — UID `1000` |
| Utilisateur cible | `root` |
| Sévérité | Faible |
| Score de risque | 21/100 |
| Statut | Clôturé |
| Motif de clôture | `benign_positive` |

## 2. Objectifs

- Vérifier la collecte des événements sudo depuis journald.
- Vérifier leur transmission sécurisée vers Elasticsearch.
- Valider l’identification de l’hôte et l’extraction des champs.
- Détecter une commande lançant un shell avec root comme utilisateur cible.
- Examiner et clôturer l’alerte.
- Vérifier qu’une commande sudo ordinaire ne déclenche pas cette règle.

## 3. Environnement

| Composant | Configuration |
|---|---|
| Système source | Debian 13 |
| Déploiement | Docker Compose |
| Elasticsearch, Kibana et Filebeat | 9.5.6 |
| Source des événements | journald |
| Index | `mini-soc-auth-*` |
| Pipeline | `mini-soc-auth-v1` |
| Transport | HTTPS avec une autorité de certification locale |
| Rétention configurée | Suppression des index après sept jours |

Filebeat utilise une clé API limitée à la publication des événements
dans les index du laboratoire.

## 4. Logique de détection

**Nom :** Mini-SOC — Shell root via sudo

**Type :** Custom Query Rule

**Langage :** KQL

**Source :** `mini-soc-auth-*`

```kql
event.dataset : "linux.auth" and
event.action : "sudo-command" and
user.effective.name : "root" and
sudo.command : (/bin/bash* or /usr/bin/bash* or /bin/sh* or /usr/bin/sh*)
```

| Paramètre | Valeur |
|---|---|
| Fréquence | Une minute |
| Fenêtre analysée | Deux dernières minutes |
| Chevauchement | Une minute |
| Sévérité | Low |
| Score de risque | 21 |

### Correspondance MITRE ATT&CK

| Niveau | Référence |
|---|---|
| Tactique | Privilege Escalation — `TA0004` |
| Technique | Abuse Elevation Control Mechanism — `T1548` |
| Sous-technique | Sudo and Sudo Caching — `T1548.003` |

Cette correspondance décrit le comportement surveillé. L’utilisation
de sudo ne prouve pas à elle seule une activité malveillante.

Référence : [MITRE ATT&CK — T1548.003](https://attack.mitre.org/techniques/T1548/003/)

## 5. Test positif — Shell root via sudo

Commande exécutée volontairement :

```bash
sudo /bin/bash -c 'true MINI_SOC_SUDO_SHELL_TEST'
```

Cette commande lance brièvement Bash avec les privilèges root.
Le shell exécute `true`, une commande sans effet, puis se termine.

### Chronologie

Tous les horaires sont en UTC.

| Horodatage | Étape | Champ de référence |
|---|---|---|
| 2026-11-03 22:00:13.526 | Création de la règle | `kibana.alert.rule.created_at` |
| 2026-11-03 22:01:51.253 | Événement source | `kibana.alert.original_time` |
| 2026-11-03 22:01:51.629 | Création de l’événement côté collecteur | `event.created` |
| 2026-11-03 22:02:16.783 | Première détection | `kibana.alert.start` |
| 2026-11-03 22:08:37.000 | Mise à jour du traitement vers l’état clôturé | `kibana.alert.workflow_status_updated_at` |

Le délai observé entre l’horodatage source et la première détection
est d’environ **25,5 secondes** pour ce test.

### Identifiants de preuve

| Élément | Valeur |
|---|---|
| ID de l’alerte | `354c1d037905ecbe2bacef4546cf4411b0052f5aa6362d42cb1fb752af0c489c` |
| ID du document source | `f0Fuo6EBwgPmZH0f5q7O` |
| Index source | `mini-soc-auth-2026.11.03` |
| ID logique de la règle | `9e8a9aaf-41b7-4055-a2d2-d5eddb6e88b3` |

### Message source

```text
taphinho : TTY=pts/0 ; PWD=/home/taphinho/mini-soc-elk ; USER=root ; COMMAND=/bin/bash -c 'true MINI_SOC_SUDO_SHELL_TEST'
```

### Champs observés

| Champ | Valeur |
|---|---|
| `host.name` | `white-hat` |
| `user.name` | `taphinho` |
| `user.id` | `1000` |
| `user.effective.name` | `root` |
| `log.syslog.appname` | `sudo` |
| `event.dataset` | `linux.auth` |
| `event.action` | `sudo-command` |
| `sudo.tty` | `pts/0` |
| `sudo.command` | `/bin/bash -c 'true MINI_SOC_SUDO_SHELL_TEST'` |
| `process.working_directory` | `/home/taphinho/mini-soc-elk` |
| `kibana.alert.workflow_status` | `closed` |
| `kibana.alert.workflow_reason` | `benign_positive` |

### Résultat

L’événement a satisfait les conditions de la règle et généré une alerte.

Le marqueur et le contexte connu permettent de rattacher cette alerte
au test autorisé. Il s’agit d’une détection correcte d’une activité
bénigne dans le laboratoire.

## 6. Test négatif — Commande sudo ordinaire

Commande témoin :

```bash
sudo /usr/bin/true MINI_SOC_NEGATIVE_TEST
```

Cette commande utilise sudo sans lancer de shell.

### Vérifications réalisées

- L’événement est présent dans les index `mini-soc-auth-*`.
- Le pipeline a enrichi le message.
- `event.action` vaut `sudo-command`.
- `sudo.command` correspond à `/usr/bin/true MINI_SOC_NEGATIVE_TEST`.
- Une exécution de la règle a réussi après le test.
- Aucune alerte correspondant au marqueur n’a été trouvée,
  tous statuts inclus.

### Résultat

La commande témoin a été collectée sans déclencher la règle.

Ce résultat valide la distinction entre les deux scénarios testés.
Il ne démontre pas l’absence de tous les faux positifs.

L’horodatage précis et l’identifiant du document du test négatif
ne sont pas consignés dans ce rapport.

## 7. Analyse et décision

Le test positif montre que la chaîne de collecte, d’enrichissement
et de détection reconnaît une commande sudo lançant un shell root.

Le test négatif confirme qu’une commande sudo ordinaire peut être
collectée et enrichie sans correspondre à la logique de détection.

**Décision :** clôture de l’alerte positive comme `benign_positive`.

Aucune mesure de confinement n’a été appliquée dans le cadre du test.

Le journal sudo ne permet pas, à lui seul, de connaître le résultat
final de la commande ni toutes les actions réalisées dans un shell.
Cette analyse concerne uniquement les scénarios contrôlés du laboratoire.

## 8. Limites

- Une activité d’administration légitime peut déclencher la règle.
- Les préfixes peuvent reconnaître des noms de programmes plus longs
  commençant par les chemins surveillés.
- D’autres shells ou modes de lancement peuvent échapper à la détection.
- La règle dépend de la collecte journald et du pipeline d’ingestion.
- Le message sudo ne prouve pas la réussite finale de la commande.
- Cette source seule ne couvre pas toutes les commandes exécutées
  ensuite dans le shell.
- La rétention des index source et celle des alertes sont distinctes :
  une alerte conservée ne garantit pas la disponibilité de son document source.
- Les deux tests ne représentent pas l’ensemble des usages possibles de sudo.

## 9. Améliorations prévues

- Consigner les identifiants et horodatages du test négatif.
- Tester plusieurs variantes de lancement de shell.
- Affiner la correspondance sur les chemins de commande.
- Documenter les activités administratives susceptibles de déclencher la règle.
- Exporter la règle, le pipeline et les modèles d’index dans Git.
- Conserver des preuves anonymisées avant expiration des logs source.
- Étudier une collecte complémentaire des exécutions de processus.

## 10. Bilan de validation

| Contrôle | Résultat |
|---|---|
| Collecte journald | Validée |
| Transmission vers Elasticsearch | Validée |
| Identification de l’hôte | Validée |
| Extraction des champs sudo | Validée |
| Alerte sur le scénario positif | Validée |
| Triage et clôture de l’alerte | Validés |
| Collecte du scénario négatif | Validée |
| Absence d’alerte sur le scénario négatif | Validée |

Le laboratoire distingue correctement les deux scénarios testés :
un shell root via sudo et une commande sudo ordinaire.
