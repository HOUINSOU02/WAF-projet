# Projet WAF Security & AI Monitoring

Ce projet implémente une solution complète de pare-feu applicatif web (WAF) avec une analyse intelligente des menaces et une visualisation en temps réel des attaques.

## 🚀 Architecture du Projet

L'infrastructure est containerisée à l'aide de Docker et repose sur plusieurs composants clés :

### 🛡️ Sécurité (BunkerWeb)
- **BunkerWeb** : Le WAF principal basé sur Nginx, configuré avec ModSecurity et les règles Core Rule Set (CRS).
- **BunkerWeb UI & Scheduler** : Interfaces de gestion et d'orchestration pour la configuration du WAF.
- **BWAPP** : Une application web délibérément vulnérable utilisée comme cible pour tester les capacités de détection.

### 🧠 Analyse & IA
- **IA Module** : Un service personnalisé (construit depuis `./ia`) dédié à l'analyse des requêtes par intelligence artificielle pour la détection d'anomalies.
- **SIEM** : Un système de gestion des événements de sécurité (construit depuis `./siem`) qui centralise les alertes en provenance de Loki et du module IA.

### 📊 Monitoring (Stack LG)
- **Loki** : Système d'agrégation de logs.
- **Promtail** : Agent qui collecte les logs des conteneurs Docker et les expédie vers Loki.
- **Grafana** : Interface de visualisation utilisant les données de Loki pour afficher un dashboard de sécurité détaillé.

## 🌐 Réseau et Adressage

Le projet utilise un réseau dédié `waf_net` (sous-réseau `10.89.1.0/24`) :
- **WAF** : `10.89.1.10` (Ports 8080/8443)
- **Application (BWAPP)** : `10.89.1.20`
- **Grafana** : `10.89.1.32` (Port 3000)
- **IA Module** : `10.89.1.40` (Port 8000)

## 📈 Dashboard de Sécurité

Le tableau de bord Grafana inclus (`monitoring/dashboard.json`) permet de suivre :
- **Attaques bloquées en temps réel** (Statut HTTP 403).
- **Classification des attaques** : SQL Injection (SQLi), Cross-Site Scripting (XSS), Local File Inclusion (LFI), et Command Injection.
- **Score d'anomalie** : Analyse des logs ModSecurity pour identifier les comportements suspects.
- **Logs IA** : Monitoring spécifique des détections effectuées par le module d'intelligence artificielle.

## 🛠️ Installation et Lancement

1. **Prérequis** : 
   - Docker et Docker Compose installés.
   - Le dossier `//waf-project/bw_data` doit être accessible pour les volumes persistants.

2. **Démarrage** :
   ```bash
   cd waf-projet
   ./start.sh
   ```

3. **Accès aux services** :
   - **Application via WAF** : `http://localhost:8080`
   - **Interface WAF** : `http://localhost:7000` (Admin: `admin` / Pass: `Admin@2024!`)
   - **Grafana** : `http://localhost:3000` (Admin: `admin` / Pass: `Admin@2024!`)

## 📂 Structure des fichiers

```text
.
├── docker-compose.yml       # Orchestration des services
├── ia/                      # Code source du module IA
├── siem/                    # Code source du SIEM
├── monitoring/              # Configuration Monitoring
│   ├── dashboard.json       # Dashboard Grafana pré-configuré
│   ├── loki-config.yml      # Configuration Loki
│   ├── promtail-config.yml  # Configuration Promtail
│   └── grafana-datasources.yml # Provisioning des sources de données
└── bw_data/                 # Données persistantes BunkerWeb
```

## 🛡️ Sécurité
Les identifiants par défaut sont fournis à des fins de développement. Pour un déploiement en production, veuillez modifier les variables d'environnement `ADMIN_PASSWORD` et `GF_SECURITY_ADMIN_PASSWORD` dans le fichier `docker-compose.yml`.

---
*Projet maintenu par Luky.*
