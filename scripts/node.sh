#!/usr/bin/env bash
# node.sh — start, stop, restart and check this device's rust_p2p_node, gracefully.
#
#   bash ~/node.sh start     start it; refuses if one is already running; waits until it says ready
#   bash ~/node.sh stop      graceful: the node refuses new jobs, says goodbye to its peers (they
#                            drop it at once), finishes in-flight work, exits. SIGKILL only if it
#                            is still running after STOP_WAIT seconds (default 45).
#   bash ~/node.sh restart   stop + start (after a rebuild, or to clear a mock temperature)
#   bash ~/node.sh check     the sync check every start ends with: one node here, node.env's
#                            settings, and every device on the mesh's newest build
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
# The node bounds its own shutdown at about 30 s (farewell 3 + requests 10 + background work 10 +
# the model server 5): give it that and some, then force it.
STOP_WAIT=${STOP_WAIT:-45}
KILL_WAIT=${KILL_WAIT:-15}   # a killed process can take seconds to go on a hot, loaded machine
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
  note "temperature $(jf thermal_c <<<"$h" | awk '{ printf "%.1f", $1 }') °C / limit $(jf max_temp <<<"$h")${mock:+   (MOCK: HARMONY_MOCK_TEMP=$mock — restart without it to use the sensor)} · model $(jf tier <<<"$h") · $(jf peers <<<"$h") peer(s)"
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
    kill -KILL $(live_pids) 2>/dev/null
    local k=0
    while [ $k -lt "$KILL_WAIT" ] && [ -n "$(live_pids)" ]; do sleep 1; k=$((k + 1)); done
  fi
  strip 2>/dev/null < "$LOG" | grep -E 'told [0-9]+/[0-9]+ peer|still in flight|did not finish|shutdown complete' | tail -n 3 \
    | sed 's/.*rust_p2p_node: /     /'
  if [ -n "$(live_pids)" ]; then
    local p st who
    for p in $(live_pids); do
      st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null); who=$(stat -c %U "/proc/$p" 2>/dev/null)
      case $st in
        D) bad "could not stop pid $p: it is stuck in the kernel (state D) and ignores even SIGKILL; only a reboot frees it";;
        *) if [ -n "$who" ] && [ "$who" != "$(id -un)" ]; then bad "could not stop pid $p: it belongs to $who (sudo kill $p)"
           else bad "could not stop pid $p (state ${st:-gone?}): ps -o pid,stat,etime,args -p $p"; fi;;
      esac
    done
    return 1
  fi
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
  # Descriptors 3-9 closed: a node must not keep whatever its starter held open, such as the lock
  # of `flock … node.sh restart` (it would hold that lock for its whole life, and the next
  # restart through the same lock would wait for it and fail).
  if command -v setsid >/dev/null; then setsid nohup "$BIN" "$@" > "$LOG" 2>&1 < /dev/null 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- &
  else nohup "$BIN" "$@" > "$LOG" 2>&1 < /dev/null 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- & fi
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
        sync_check
        return 0
      fi
    fi
    sleep 0.5; t=$((t + 1))
  done
  warn "not ready after ${START_WAIT}s (still bootstrapping?)"; status
}

# ---- sync check: after every start, and on its own with  bash ~/node.sh check
# Is this device running one node, with the settings node.env asks for, on the mesh's newest build,
# and are the other devices on it too? It only reads, and says what to run when something is off.
# The laptop knows the build the phone last signed for the notebook (~/harmony_win_update/BUILD),
# what the notebook installed (DEPLOYED) and when its watcher last reported; the phone asks the
# laptop for those and its build in one ssh (HARMONY_SYNC_SSH in node.env, else joe@ the laptop in
# HARMONY_PEERS). The notebook checks the laptop by itself every 15 s and installs a newer build.
# SYNC_CHECK=0 skips it.
tagnum() { local t=${1#harmony-v}; case $t in ''|*[!0-9]*) echo 0;; *) echo "$t";; esac; }
node_list() {  # every rust_p2p_node on this device, any user: "pid user"
  local p
  { live_pids; is_phone || ps -e -o pid=,comm= 2>/dev/null | awk '$2 == "rust_p2p_node" { print $1 }'; } | sort -un |
    while read -r p; do [ -d "/proc/$p" ] && echo "$p $(stat -c %U "/proc/$p" 2>/dev/null)"; done
}
sync_check() {
  [ "${SYNC_CHECK:-1}" = 0 ] && return 0
  local h port me n p u maxt tier mode want off="" view to seed newest=0 d b sum="" behind="" said age
  printf '%s== sync check ==%s\n' "$C" "$N"
  port=$(log_port); h=$(health "${port:-3005}")
  me=$(jf build <<<"$h")
  [ -n "$me" ] || { warn "the node does not answer yet: nothing to compare (later: bash ~/node.sh check)"; return 0; }
  # 1. one node on this device, running what node.env asks for (a test can leave a temporary limit)
  n=$(node_list | wc -l)
  if [ "$n" -gt 1 ]; then
    warn "$n nodes run on this device; one is expected:"
    node_list | while read -r p u; do note "pid $p ($u): $(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | cut -c1-90)"; done
    note "stop them all, then start one: bash ~/node.sh stop; bash ~/node.sh start   (owned by root: sudo kill <pid>)"
  fi
  [ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
  maxt=$(jf max_temp <<<"$h"); tier=$(jf tier <<<"$h"); mode=$(jf trust <<<"$h" | jf mode)
  want=${HARMONY_MAX_TEMP_C:-65}
  [ -n "$maxt" ] && awk -v a="$maxt" -v b="$want" 'BEGIN { exit !(a + 0 != b + 0) }' && off+=" limit $maxt °C (node.env: $want °C);"
  [ -n "${HARMONY_TRUST_MODE:-}" ] && [ -n "$mode" ] && [ "$mode" != "$HARMONY_TRUST_MODE" ] && off+=" $mode trust (node.env: $HARMONY_TRUST_MODE);"
  if [ -n "${HARMONY_MODEL_TIER:-}" ]; then case $tier in "$HARMONY_MODEL_TIER"*) ;; *) off+=" model $tier (node.env: $HARMONY_MODEL_TIER);";; esac; fi
  if [ -n "$off" ]; then warn "it runs with settings node.env does not have:${off%;} (a test left them?): bash ~/node.sh restart"
  elif [ "$n" -le 1 ]; then ok "one node here, with node.env's settings (limit $maxt °C, ${mode:-?} trust, $tier)"; fi
  # 2. builds: the newest one anywhere is the mesh build; a device below it is behind
  if [ -d "$HOME/harmony_win_update" ]; then
    view="laptop $me
staged $(cat "$HOME/harmony_win_update/BUILD" 2>/dev/null)
notebook $(cat "$HOME/harmony_win_update/DEPLOYED" 2>/dev/null)
$(f=$HOME/.harmony/notebook.status; [ -f "$f" ] && read -r t s < "$f" && echo "said $(( $(date +%s) - t )) $s")"
  else
    to=${HARMONY_SYNC_SSH:-}
    if [ -z "$to" ]; then seed=${HARMONY_PEERS:-}; seed=${seed%%,*}; seed=${seed%:*}; [ -n "$seed" ] && to=joe@$seed; fi
    [ -n "$to" ] || { note "no laptop known (HARMONY_PEERS): builds not compared"; return 0; }
    view=$(ssh -o BatchMode=yes -o ConnectTimeout=5 "$to" 'p=$(sed "s/\x1b\[[0-9;]*m//g" ~/p2p.log 2>/dev/null | grep -aoE "mesh API on http://[^ ]+" | tail -n 1 | grep -oE "[0-9]+$")
      echo "laptop $(curl -s --max-time 3 http://127.0.0.1:${p:-3005}/health | grep -o "\"build\":\"[^\"]*\"" | cut -d\" -f4)"
      echo "staged $(cat ~/harmony_win_update/BUILD 2>/dev/null)"
      echo "notebook $(cat ~/harmony_win_update/DEPLOYED 2>/dev/null)"
      f=~/.harmony/notebook.status; [ -f "$f" ] && read -r t s < "$f" && echo "said $(( $(date +%s) - t )) $s"; true' 2>/dev/null)
    [ -n "$view" ] || { warn "could not reach the laptop over ssh ($to): builds not compared"; return 0; }
    view="phone $me
$view"
  fi
  while read -r d b _; do
    case $d in phone|laptop|staged|notebook) [ "$(tagnum "$b")" -gt "$newest" ] && newest=$(tagnum "$b");; esac
  done <<<"$view"
  while read -r d b _; do
    case $d in
      phone|laptop|notebook)
        if [ -z "$b" ]; then sum+=" $d ?"
        elif [ "$(tagnum "$b")" -lt "$newest" ]; then sum+=" $d $b (behind)"; behind+=" $d"
        else sum+=" $d ✓"; fi;;
      staged) [ -n "$b" ] && [ "$(tagnum "$b")" -lt "$newest" ] && { sum+=" (staged for the notebook: $b)"; behind+=" staged"; };;
    esac
  done <<<"$view"
  if [ -z "$behind" ]; then ok "mesh build harmony-v$newest:$sum"
  else
    warn "mesh build harmony-v$newest:$sum"
    case $behind in
      *phone*|*laptop*|*staged*) note "bring them up: SKIP_TESTS=1 bash mesh_upgrade.sh (on the phone)";;
      *) note "the notebook installs the staged build by itself within 15 s; if it does not, run the autosync line there (mesh_upgrade.sh prints it)";;
    esac
  fi
  # 3. the notebook's watcher (node.ps1 v19.1+ reports every change, and every 5 minutes)
  said=$(grep '^said ' <<<"$view"); age=$(awk '{ print $2 }' <<<"$said")
  if [ -z "$said" ]; then note "notebook watcher: no report yet (node.ps1 older than v19.1, or autosync off)"
  elif [ "${age:-0}" -gt 420 ]; then warn "notebook watcher: last report $((age / 60)) min ago (notebook asleep? else run the autosync line there): ${said#said * }"
  else note "notebook watcher: reported $((age / 60)) min ago: ${said#said * }"; fi
  return 0
}

case $CMD in
  start)   start "$@";;
  stop)    stop;;
  restart) stop && start "$@";;
  status)  status;;
  check)   status && sync_check;;
  log|logs) tail -n 40 -f "$LOG";;
  *) echo "usage: bash ~/node.sh start|stop|restart|status|check|log   (env: HARMONY_MOCK_TEMP, STOP_WAIT, START_WAIT, SYNC_CHECK=0)"; exit 2;;
esac
