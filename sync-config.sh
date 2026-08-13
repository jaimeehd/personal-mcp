#!/usr/bin/env bash
# ============================================================
# personal-mcp sync-config.sh (Linux/macOS)
# ============================================================
# Sincroniza (unidireccional) el config.json oficial hacia la copia-espejo
# dentro del repo.
#
# La configuración REAL que carga el servidor vive en ~/.personal-mcp/config.json
# (ver AppConfig.default_path() en src/config.py). Esa es la ÚNICA fuente de verdad.
#
# La copia dentro de este repo (config.json, junto a este script) es solo un ESPEJO
# de solo lectura, pensado para poder verla junto al código versionado sin tener que
# navegar a la carpeta de usuario. Editar la copia del repo NO tiene ningún efecto
# sobre el servidor en ejecución.
#
# Este script siempre copia oficial -> repo. Nunca al revés. Si el config oficial
# tiene JSON inválido, el script se detiene sin tocar el espejo, para no propagar
# un archivo roto.
#
# Uso:
#   ./sync-config.sh
# ============================================================

set -euo pipefail

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

OFFICIAL_CONFIG="$HOME/.personal-mcp/config.json"
REPO_CONFIG_MIRROR="$(dirname "$(readlink -f "$0")")/config.json"

echo -e "${CYAN}=== Sincronizando config.json (oficial -> espejo del repo) ===${NC}"

if [ ! -f "$OFFICIAL_CONFIG" ]; then
    echo -e "${RED}ERROR: no se encontro el config oficial en $OFFICIAL_CONFIG${NC}"
    echo -e "${RED}Nada que sincronizar. Verifica que personal-mcp este instalado (install.sh).${NC}"
    exit 1
fi

# Validate JSON before copying
if ! python3 -m json.tool "$OFFICIAL_CONFIG" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: el config oficial tiene JSON invalido. No se toca el espejo.${NC}"
    echo -e "${RED}Detalle:${NC}"
    python3 -m json.tool "$OFFICIAL_CONFIG" 2>&1 | head -20
    exit 1
fi

cp "$OFFICIAL_CONFIG" "$REPO_CONFIG_MIRROR"

echo -e "${GREEN}OK: espejo actualizado en $REPO_CONFIG_MIRROR${NC}"
echo ""
echo -e "${YELLOW}Recordatorio importante:${NC}"
echo -e "${YELLOW}  Este archivo (config.json en el repo) es SOLO de lectura/consulta.${NC}"
echo -e "${YELLOW}  El unico archivo que el servidor realmente usa es:${NC}"
echo -e "${YELLOW}  $OFFICIAL_CONFIG${NC}"
echo ""
echo -e "${CYAN}Para entender que significa cada campo, ver CONFIG-GUIA.md en esta misma carpeta.${NC}"