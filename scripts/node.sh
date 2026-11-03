#!/usr/bin/env bash
# node.sh — start, stop, restart and check this device's rust_p2p_node, gracefully.
#
#   bash ~/node.sh start     start it; refuses if one is already running; waits until it says ready
#   bash ~/node.sh stop      graceful: the node refuses new jobs, says goodbye to its peers (they
#                            drop it at once), finishes in-flight work, exits. SIGKILL only if it
#                            is still running after STOP_WAIT seconds (default 30).
#   bash ~/node.sh restart   stop + start (after a rebuild, or to clear a mock temperature)
#   bash ~/node.sh status    which build answers, its pid, state, temperature, peers, AI placement
#   bash ~/node.sh log       follow the node's log
#
#   HARMONY_MOCK_TEMP=80 bash ~/node.sh restart     demo: report 80 °C until the next restart
#   bash ~/node.sh restart --max-temp 45            extra flags pass through to this start only
#
# Same script on the phone and the laptop. Settings live in ~/.harmony/node.env as HARMONY_*
# variables (mesh_upgrade.sh writes it). Without one, it is created from the running node's flags,
# or from defaults: phone → peer 192.168.1.192:3005, laptop → peer 192.168.1.110:3005.
set -u
GW=${GW_DIR:-$HOME/harmony_gateway}
BIN=$GW/target/release/rust_p2p_node
LOG=$HOME/p2p.log
ENV_FILE=$HOME/.harmony/node.env
STOP_WAIT=${STOP_WAIT:-30}
START_WAIT=${START_WAIT:-45}
CMD=${1:-status}
[ $# -gt 0 ] && shift

G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' C=$'\e[36m' N=$'\e[0m'
ok()   { printf '%sOK%s   %s\n' "$G" "$N" "$*"; }
warn() { printf '%sWARN%s %s\n' "$Y" "$N" "$*"; }
bad()  { printf '%sFAIL%s %s\n' "$R" "$N" "$*"; }
note() { printf '     %s\n' "$*"; }
is_phone() { [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux/files ]; }
strip() { sed 's/\x1b\[[0-9;]*m//g'; }

# Processes holding a Harmony identity lock (abstract socket @harmony-node-…): whatever their
# name, they ARE running nodes. Needs /proc/net/unix (readable in Termux and on Linux).
lock_holders() {
  local inos d f
  inos=$(awk '$NF ~ /^@harmony-node-/ {print $7}' /proc/net/unix 2>/dev/null | sort -u)
  [ -n "$inos" ] || return 0
  for d in /proc/[0-9]*; do
    for f in "$d"/fd/*; do
      case $(readlink "$f" 2>/dev/null) in
        socket:\[*\]) local i; i=$(readlink "$f"); i=${i#socket:[}; i=${i%]}
                      grep -qx "$i" <<<"$inos" && { echo "${d#/proc/}"; break; };;
      esac
    done
  done
}
# live (non-zombie) rust_p2p_node processes of this user. Matched on the executable and argv, not
# only the process name: on some Android setups the name is the linker's or truncated, which made
# `pgrep -x rust_p2p_node` miss a running node. Test binaries (rust_p2p_node-<hash>) do not match.
live_pids() {
  local d p exe a0 a1
  { for d in /proc/[0-9]*; do
      p=${d#/proc/}
      exe=$(readlink "$d/exe" 2>/dev/null); exe=${exe% (deleted)}
      a0="" a1=""; { IFS= read -r -d "" a0; IFS= read -r -d "" a1; } 2>/dev/null < "$d/cmdline"
      if [ "${exe##*/}" = rust_p2p_node ] || [ "${a0##*/}" = rust_p2p_node ] \
         || { case ${a0##*/} in linker|linker64) true;; *) false;; esac && [ "${a1##*/}" = rust_p2p_node ]; }; then
        echo "$p"
      fi
    done
    lock_holders; } | sort -un | while read -r p; do
      [ "$p" = "$$" ] && continue
      [ "$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)" = Z ] || echo "$p"
    done
}
main_pid() { live_pids | head -n 1; }
log_port() { strip < "$LOG" 2>/dev/null | grep -oE 'mesh API on http://[^ ]+' | tail -n 1 | grep -oE '[0-9]+$'; }
health() { curl -s --max-time 3 "http://127.0.0.1:${1:-3005}/health" 2>/dev/null; }
# top-level JSON field: jq if present, else python3
jf() {
  if command -v jq >/dev/null; then jq -r --arg k "$1" '.[$k] | if . == null then "" elif type == "object" or type == "array" then tojson else tostring end' 2>/dev/null
  else python3 -c 'import json,sys
try: v = json.load(sys.stdin).get(sys.argv[1])
except Exception: v = None
print("" if v is None else (json.dumps(v) if isinstance(v, (dict, list)) else str(v).lower() if isinstance(v, bool) else v))' "$1"; fi
}

# ~/.harmony/node.env: create it once, from the running node's flags or from defaults
ensure_env() {
  [ -s "$ENV_FILE" ] && return 0
  mkdir -p "${ENV_FILE%/*}"
  local pid args=() i=0 out=""
  pid=$(main_pid)
  if [ -n "$pid" ]; then
    mapfile -d '' -t args < "/proc/$pid/cmdline"
    while [ $i -lt ${#args[@]} ]; do
      case ${args[$i]} in
        --peer)       out+="HARMONY_PEERS=${args[$((i+1))]}"$'\n'; i=$((i+2)); continue;;
        --cmd-allow)  out+="HARMONY_CMD_ALLOW=${args[$((i+1))]}"$'\n'; i=$((i+2)); continue;;
        --llama-bin)  out+="HARMONY_LLAMA_BIN=${args[$((i+1))]}"$'\n'; i=$((i+2)); continue;;
        --model-tier) out+="HARMONY_MODEL_TIER=${args[$((i+1))]}"$'\n'; i=$((i+2)); continue;;
        --max-temp)   out+="HARMONY_MAX_TEMP_C=${args[$((i+1))]}"$'\n'; i=$((i+2)); continue;;
        --label)      out+="HARMONY_LABEL=${args[$((i+1))]}"$'\n'; i=$((i+2)); continue;;
      esac
      i=$((i+1))
    done
  fi
  if [ -z "$out" ]; then
    if is_phone; then
      out="HARMONY_PEERS=192.168.1.192:3005"$'\n'
    else
      local lb=$HOME/llama.cpp/build/bin/llama-completion
      [ -x "$lb" ] || lb=$HOME/llama.cpp/build/bin/llama-cli
      out="HARMONY_PEERS=192.168.1.110:3005"$'\n'"HARMONY_LLAMA_BIN=$lb"$'\n'
      warn "no HARMONY_CMD_ALLOW yet: this laptop will not accept the phone's directives until mesh_upgrade.sh writes it"
    fi
  fi
  printf '# rust_p2p_node settings for node.sh (HARMONY_* variables, one per line)\n%s' "$out" > "$ENV_FILE"
  note "settings saved to $ENV_FILE"
}

status() {
  local pid exe mock port h state build
  pid=$(main_pid)
  if [ -z "$pid" ]; then bad "not running   (start: bash ~/node.sh start)"; return 1; fi
  [ "$(live_pids | wc -l)" -gt 1 ] && warn "more than one rust_p2p_node is running: $(live_pids | tr '\n' ' ')"
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
  mock=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^HARMONY_MOCK_TEMP=//p')
  port=$(log_port); port=${port:-3005}
  h=$(health "$port")
  if [ -z "$h" ]; then bad "pid $pid is running but nothing answers on :$port"; return 1; fi
  state=$(jf state <<<"$h"); build=$(jf build <<<"$h")
  ok "pid $pid · ${build:-pre-v10 build} · ${state:-ready} · :$port · $(jf label <<<"$h") $(jf node <<<"$h" | cut -c1-12)"
  case $exe in *" (deleted)") warn "running an old binary (rebuilt since it started): bash ~/node.sh restart";; esac
  local hp; hp=$(jf pid <<<"$h")
  [ -n "$hp" ] && [ "$hp" != "$pid" ] && warn "the node answering on :$port is pid $hp, not $pid"
  note "temperature $(jf thermal_c <<<"$h") °C / limit $(jf max_temp <<<"$h")${mock:+   (MOCK: HARMONY_MOCK_TEMP=$mock — restart without it to use the sensor)} · model $(jf tier <<<"$h") · $(jf peers <<<"$h") peer(s)"
  local pl; pl=$(jf placement <<<"$h")
  if [ -n "$pl" ]; then note "AI placement: jobs → $(jf target_name <<<"$pl") ($(jf reason <<<"$pl"))$( [ -n "$(jf veto_now <<<"$pl")" ] && echo " — vetoed: $(jf veto_now <<<"$pl")")"; fi
  [ -n "$build" ] && note "dashboard: http://127.0.0.1:$port/ui"
  return 0
}

stop() {
  local pids t=0
  pids=$(live_pids | tr '\n' ' ')
  if [ -z "${pids// /}" ]; then ok "not running"; is_phone && command -v termux-wake-unlock >/dev/null && termux-wake-unlock; return 0; fi
  # shellcheck disable=SC2086
  kill -TERM $pids 2>/dev/null
  note "stopping pid ${pids% }: refusing new jobs, saying goodbye to peers, finishing in-flight work"
  while [ $t -lt "$STOP_WAIT" ] && [ -n "$(live_pids)" ]; do
    sleep 1; t=$((t + 1))
    [ $((t % 5)) -eq 0 ] && note "… ${t}s"
  done
  if [ -n "$(live_pids)" ]; then
    warn "still running after ${STOP_WAIT}s: forcing it (SIGKILL)"
    # shellcheck disable=SC2046
    kill -KILL $(live_pids) 2>/dev/null; sleep 1
  fi
  strip < "$LOG" 2>/dev/null | grep -E 'told [0-9]+/[0-9]+ peer|still in flight|did not finish|shutdown complete' | tail -n 3 \
    | sed 's/.*rust_p2p_node: /     /'
  if [ -n "$(live_pids)" ]; then bad "could not stop pid $(live_pids | tr '\n' ' ')"; return 1; fi
  ok "stopped after ${t}s"
  is_phone && command -v termux-wake-unlock >/dev/null && termux-wake-unlock
  return 0
}

start() {
  local pid port h t=0 hpid state
  pid=$(main_pid)
  if [ -n "$pid" ]; then warn "already running (pid $pid); to restart: bash ~/node.sh restart"; status; return 0; fi
  [ -x "$BIN" ] || { bad "$BIN is not built (cd $GW && cargo build --release)"; return 1; }
  ensure_env
  set -a; . "$ENV_FILE"; set +a
  [ -n "${HARMONY_MOCK_TEMP:-}" ] && warn "demo mode: this node will report ${HARMONY_MOCK_TEMP} °C until the next restart"
  is_phone && command -v termux-wake-lock >/dev/null && termux-wake-lock
  [ -s "$LOG" ] && mv -f "$LOG" "$LOG.1"
  cd "$GW" || return 1
  if command -v setsid >/dev/null; then setsid nohup "$BIN" "$@" > "$LOG" 2>&1 < /dev/null &
  else nohup "$BIN" "$@" > "$LOG" 2>&1 < /dev/null & fi
  pid=$!
  cd - >/dev/null || true
  note "starting pid $pid ($(grep -oE '^[A-Z_]+=' "$ENV_FILE" | tr -d '=' | tr '\n' ' ')from $ENV_FILE)"
  while [ $t -lt $((START_WAIT * 2)) ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      bad "it exited during startup:"
      strip < "$LOG" | grep -iE 'error|already running|in use|refus|panick' | tail -n 3 | sed 's/^/     /'
      [ -s "$LOG" ] || note "(empty log)"
      if grep -q 'already running' "$LOG" 2>/dev/null; then
        local h; for h in $(live_pids); do
          note "held by pid $h: $(tr '\0' ' ' < "/proc/$h/cmdline" 2>/dev/null | cut -c1-120)"
        done
        note "stop it gracefully with: bash ~/node.sh stop   (then start again)"
      fi
      return 1
    fi
    port=$(log_port)
    if [ -n "$port" ]; then
      h=$(health "$port")
      state=$(jf state <<<"$h"); hpid=$(jf pid <<<"$h")
      if [ -n "$hpid" ] && [ "$hpid" != "$pid" ]; then
        bad "another node (pid $hpid) answers on :$port, not the one just started"; return 1
      fi
      if [ "$state" = ready ] || { [ -n "$h" ] && [ -z "$state" ]; }; then
        ok "ready after $((t / 2))s"
        status
        return 0
      fi
    fi
    sleep 0.5; t=$((t + 1))
  done
  warn "not ready after ${START_WAIT}s (still bootstrapping?)"; status
}

case $CMD in
  start)   start "$@";;
  stop)    stop;;
  restart) stop && start "$@";;
  status)  status;;
  log|logs) tail -n 40 -f "$LOG";;
  *) echo "usage: bash ~/node.sh start|stop|restart|status|log   (env: HARMONY_MOCK_TEMP, STOP_WAIT, START_WAIT)"; exit 2;;
esac
