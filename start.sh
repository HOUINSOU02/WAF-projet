#!/bin/bash

# Check for .env file to avoid password warnings
if [ ! -f .env ]; then
    echo "⚠️  Attention : le fichier .env est introuvable. Utilisation des mots de passe par défaut."
fi

# Fix socket permissions
chmod 777 $XDG_RUNTIME_DIR/podman/podman.sock

cd ~/waf-project

# Création du répertoire de données si nécessaire
mkdir -p bw_data

# --- Nettoyage Forcé ---
echo "Nettoyage complet pour libérer le sous-réseau 10.89.1.0/24..."

# 1. Arrêt des services et suppression des orphelins
docker compose down --remove-orphans || true

# 2. Suppression forcée du réseau spécifique (via Docker et Podman)
docker network rm waf_net 2>/dev/null || true
podman network rm -f waf_net 2>/dev/null || true

# 3. Purge des réseaux CNI résiduels de Podman (libère les sous-réseaux bloqués)
podman network prune -f

# 4. Vérification de conflit sur l'hôte
if ip addr show | grep -q "10.89.1.1"; then
    echo "⚠️  Attention : L'interface réseau de l'hôte utilise encore 10.89.1.1."
    echo "Si le démarrage échoue, tapez : sudo ip link delete cni-podman0 (ou le nom de l'interface concernée)"
fi

sleep 2

# Start stack
if ! docker compose up -d --build; then
    echo "❌ Échec du démarrage. Vérifiez si l'IP 10.89.1.1 est utilisée par votre hôte."
    exit 1
fi

echo "Attente démarrage BunkerWeb..."
sleep 10

printf "Attente chargement des règles ModSecurity "
# Augmentation du délai (30 tentatives) et détection de l'état prêt de Nginx
for i in $(seq 1 30); do
  if docker logs waf-project-bunkerweb-1 2>&1 | grep -qiE "ModSecurity: Engine is switched to: On|Nginx is running|ready to handle connections"; then
    printf " ✅\n"
    break
  fi
  printf "."
  sleep 3
done

# Attente que Loki soit ready (max 30s)
printf "Attente que Loki soit prêt "
for i in $(seq 1 10); do
  STATUS=$(curl -s http://127.0.0.1:3100/ready 2>/dev/null)
  if [ "$STATUS" = "ready" ]; then
    printf " ✅\n"
    break
  fi
  printf "."
  sleep 3
done

# Redémarre le SIEM après que Loki soit prêt
docker compose restart siem
echo "✅ SIEM redémarré"

echo "Vérification des services critiques..."
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "========================================="
echo "        Stack WAF démarrée !             "
echo "========================================="
echo "Grafana            : http://127.0.0.1:3000"
echo "WAF (Entrée)       : http://127.0.0.1:8080"
echo "Proxy WAF-IA       : http://127.0.0.1:9000"
echo "BunkerWeb UI       : http://127.0.0.1:7000"
echo "bWAPP (Direct)     : http://127.0.0.1:8888"
echo "Module IA (API)    : http://127.0.0.1:8000"
echo "SIEM Dashboard     : http://127.0.0.1:5001"
echo "========================================="
echo "ℹ️  Si bWAPP ne répond pas, vérifiez 'docker logs bwapp'"
