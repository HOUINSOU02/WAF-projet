#!/bin/bash
# Fix socket permissions
chmod 777 $XDG_RUNTIME_DIR/podman/podman.sock

# Start stack
cd ~/waf-project
docker compose up -d

echo "Attente démarrage BunkerWeb..."
sleep 15

# Fix API whitelist permanente
docker exec waf-project-bunkerweb-1 sed -i 's/API_WHITELIST_IP=127.0.0.0\/8$/API_WHITELIST_IP=127.0.0.0\/8 10.89.1.0\/24/' /etc/nginx/variables.env
docker exec waf-project-bunkerweb-1 nginx -s reload

echo "Attente chargement règles ModSecurity..."
sleep 20

# Attente que Loki soit ready (max 30s)
echo "Attente que Loki soit prêt..."
for i in $(seq 1 10); do
  STATUS=$(curl -s http://127.0.0.1:3100/ready 2>/dev/null)
  if [ "$STATUS" = "ready" ]; then
    echo "✅ Loki prêt !"
    break
  fi
  echo "   Loki pas encore prêt ($i/10)..."
  sleep 3
done

# Redémarre le SIEM après que Loki soit prêt
docker compose restart siem
echo "✅ SIEM redémarré"

echo ""
echo "========================================="
echo "        Stack WAF démarrée !             "
echo "========================================="
echo "Grafana        : http://127.0.0.1:3000"
echo "WAF            : http://127.0.0.1:8080"
echo "BunkerWeb UI   : http://127.0.0.1:7000"
echo "bWAPP (vulnérable) : http://127.0.0.1:8888"
echo "Module IA      : http://127.0.0.1:8000"
echo "SIEM Dashboard : http://127.0.0.1:5001"
echo "========================================="
