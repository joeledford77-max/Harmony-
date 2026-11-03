#!/usr/bin/env bash
# win_node.sh — add a Windows PC to the mesh as a node. Run ON THE PHONE, after mesh_upgrade.sh (v12).
#
#   bash win_node.sh [user@laptop-ip]            default: joe@192.168.1.192
#   NOTEBOOK_TIER=standard bash win_node.sh      send the 3B model instead of the 1B (wants 8 GB RAM)
#   NOTEBOOK_LABEL=notebook (default)            the new node's name in the mesh and in directives
#
# The laptop cross-compiles rust_p2p_node.exe for Windows, so nothing heavy is installed on the PC,
# and stages it in ~/harmony_win with the model, the settings and the Windows scripts. Then one
# line in PowerShell on the PC copies that folder over and runs setup_windows.ps1.
# Needs in ~/storage/downloads (tap the cards in the chat): node.ps1, node.cmd, setup_windows.ps1.
# The new node is a worker: it reports its vitals, takes offloaded jobs and shows up in Llama's
# prompt; it does not run advisories, so the laptop's Llama stays the one that decides.
set -euo pipefail

LAPTOP=${1:-joe@192.168.1.192}
LIP=${LAPTOP#*@}
DL=$HOME/storage/downloads
TIER=${NOTEBOOK_TIER:-light}
LABEL=${NOTEBOOK_LABEL:-notebook}
TARGET=x86_64-pc-windows-gnu
G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' C=$'\e[36m' N=$'\e[0m'
step() { printf '\n%s== %s ==%s\n' "$C" "$*" "$N"; }
ok()   { printf '%sOK%s   %s\n' "$G" "$N" "$*"; }
warn() { printf '%sWARN%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%sSTOP%s %s\n' "$R" "$N" "$*"; exit 1; }
logport() { sed 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null | grep -oE 'mesh API on http://[^ ]+' | tail -n 1 | grep -oE '[0-9]+$' || true; }
newest() { ls -t "$DL"/$1 2>/dev/null | head -n 1 || true; }

case $TIER in light|standard) ;; *) die "NOTEBOOK_TIER is light or standard";; esac
[[ $LABEL =~ ^[a-z0-9-]{1,24}$ ]] || die "NOTEBOOK_LABEL: up to 24 lowercase letters, digits or dashes"

# ------------------------------------------------------------------ 1. scripts
step "1/4 Windows scripts"
NPS=$(newest 'node*.ps1'); NCMD=$(newest 'node*.cmd'); SETUP=$(newest 'setup_windows*.ps1')
{ [ -n "$NPS" ] && grep -q 'node.ps1 - start, stop' "$NPS"; } || die "node.ps1 not in Downloads: download it from the chat"
{ [ -n "$NCMD" ] && grep -q 'node.ps1' "$NCMD"; } || die "node.cmd not in Downloads: download it from the chat"
{ [ -n "$SETUP" ] && grep -q 'setup_windows.ps1 - make this Windows PC' "$SETUP"; } \
  || die "setup_windows.ps1 not in Downloads: download it from the chat"
# keep copies in ~ (publish_repo.sh puts them in the repo)
cp -f "$NPS" "$HOME/node.ps1"; cp -f "$NCMD" "$HOME/node.cmd"; cp -f "$SETUP" "$HOME/setup_windows.ps1"
[ "$(readlink -f "$0")" = "$HOME/win_node.sh" ] || cp -f "$0" "$HOME/win_node.sh" 2>/dev/null || true
ok "node.ps1, node.cmd, setup_windows.ps1 · new node: \"$LABEL\", ${TIER} model"

# ------------------------------------------------------------------ 2. toolchain on the laptop
step "2/4 laptop $LAPTOP: Windows cross-compiler"
ssh -o ConnectTimeout=8 "$LAPTOP" true || die "cannot ssh to $LAPTOP"
PHONE_IP=$(ssh "$LAPTOP" 'echo ${SSH_CLIENT%% *}')
[ -n "$PHONE_IP" ] || die "could not learn this phone's IP from $LAPTOP"
if ! ssh "$LAPTOP" 'command -v x86_64-w64-mingw32-gcc >/dev/null'; then
  warn "installing the MinGW-w64 cross-compiler on the laptop: type the laptop's password when sudo asks"
  ssh -t "$LAPTOP" 'sudo sh -c "apt-get update -qq; apt-get install -y gcc-mingw-w64-x86-64"' \
    || die "could not install gcc-mingw-w64-x86-64 on the laptop"
fi
ssh "$LAPTOP" bash -s <<'REMOTE' || die "Rust toolchain setup failed on the laptop (output above)"
set -e
source "$HOME/.cargo/env"
v=$(rustc --version | awk '{print $2}')
# Windows file locking (the node's identity lock there) needs Rust 1.89 or newer
if ! awk -v v="$v" 'BEGIN { split(v, a, "."); exit !(a[1] > 1 || (a[1] == 1 && a[2] >= 89)) }'; then
  echo "rustc $v is older than 1.89: updating"
  rustup update stable
fi
rustup target add x86_64-pc-windows-gnu 2>&1 | tail -n 1
echo "  $(rustc --version) · $(x86_64-w64-mingw32-gcc --version | head -n 1)"
REMOTE
ok "MinGW-w64 and the Windows target are ready"

# ------------------------------------------------------------------ 3. build
step "3/4 laptop: build rust_p2p_node.exe for Windows"
ssh "$LAPTOP" bash -s -- "$TARGET" <<'REMOTE' || die "the Windows build failed on the laptop (first errors above; full log: ~/win_build.log there)"
set -eo pipefail
source "$HOME/.cargo/env"
cd ~/harmony_gateway
grep -q 'fn post_shutdown' src/main.rs || { echo "the laptop's src/main.rs is older than v12: run mesh_upgrade.sh first"; exit 3; }
echo "cargo build --release --target $1 (several minutes the first time)…"
if ! cargo build --release --target "$1" > ~/win_build.log 2>&1; then
  grep -E '^error' -A 12 ~/win_build.log | head -n 40
  exit 4
fi
exe=target/$1/release/rust_p2p_node.exe
grep -qaF 'harmony-v12' "$exe" || { echo "built, but $exe is not harmony-v12"; exit 5; }
echo "  $exe ($(( $(stat -c %s "$exe") / 1048576 )) MB)"
REMOTE
ok "rust_p2p_node.exe built (harmony-v12)"

# ------------------------------------------------------------------ 4. stage
step "4/4 laptop: stage ~/harmony_win"
PPORT=$(logport "$HOME/p2p.log"); PPORT=${PPORT:-3005}
LPORT=$(ssh "$LAPTOP" "sed 's/\x1b\[[0-9;]*m//g' ~/p2p.log | grep -oE 'mesh API on http://[^ ]+' | tail -n 1 | grep -oE '[0-9]+\$'" 2>/dev/null || true)
LPORT=${LPORT:-3005}
ssh "$LAPTOP" 'rm -rf ~/harmony_win && mkdir -p ~/harmony_win'
scp -q "$HOME/node.ps1" "$HOME/node.cmd" "$HOME/setup_windows.ps1" "$LAPTOP:harmony_win/"
ssh "$LAPTOP" bash -s -- "$TARGET" "$TIER" "$LABEL" "$PHONE_IP:$PPORT" "$LIP:$LPORT" <<'REMOTE' || die "staging failed on the laptop (output above)"
set -e
W=$HOME/harmony_win; GW=$HOME/harmony_gateway
exe=$GW/target/$1/release/rust_p2p_node.exe
cp -f "$exe" "$W/"
# DLLs the .exe imports that Windows does not ship (MinGW's runtime, if it was linked dynamically)
for dll in $(x86_64-w64-mingw32-objdump -p "$exe" | sed -n 's/^[[:space:]]*DLL Name: //p'); do
  f=$(x86_64-w64-mingw32-gcc -print-file-name="$dll")
  if [ "$f" != "$dll" ] && [ -f "$f" ]; then cp -f "$f" "$W/"; echo "  bundled $dll"; fi
done
case $2 in standard) m=llama-3.2-3b-instruct.gguf;; *) m=llama-3.2-1b-instruct.gguf;; esac
[ -e "$GW/$m" ] || { echo "the laptop has no $GW/$m"; exit 5; }
ln "$GW/$m" "$W/$m" 2>/dev/null || cp "$GW/$m" "$W/$m"
# settings for node.ps1; setup_windows.ps1 adds the llama.cpp, tier and model lines
printf '%s\r\n' "# rust_p2p_node settings for node.ps1 (HARMONY_* lines), written by win_node.sh" \
  "HARMONY_PEERS=$4,$5" "HARMONY_LABEL=$3" > "$W/harmony.env"
sed -i 's/\r*$/\r/' "$W/node.cmd"   # cmd.exe wants CRLF
ls -l "$W" | tail -n +2 | awk '{ printf "  %-32s %8.1f MB\n", $9, $5 / 1048576 }'
REMOTE
ok "staged: peers $PHONE_IP:$PPORT (phone) and $LIP:$LPORT (laptop), label \"$LABEL\""

echo
echo "On the Windows PC: open PowerShell (Start, type powershell, Enter) and type this one line."
echo "scp asks to trust the laptop the first time (type yes) and for the laptop's password:"
echo
printf '  mkdir -Force ~\\harmony | Out-Null; cd ~\\harmony; scp "%s:harmony_win/*" .; powershell -ExecutionPolicy Bypass -File .\\setup_windows.ps1\n' "$LAPTOP"
echo
echo "Setup downloads llama.cpp for Windows, asks once for admin (one firewall rule), and starts the node."
echo "Then here:  bash ~/node.sh status     (2 peers)    and the dashboard shows three devices."
