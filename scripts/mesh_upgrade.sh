#!/usr/bin/env bash
# mesh_upgrade.sh — build rust_p2p_node on this phone and the laptop, then restart both
# gracefully with node.sh, and check that the new build is what answers. The laptop is set up to
# accept this phone's directives (--cmd-allow). Either node may rotate off 3005; the script follows.
# If a Windows notebook was set up from the laptop (win_node.sh), the laptop also builds the same
# version for it and stages it in ~/harmony_win_update with node.ps1; this phone signs the staged
# files, and the notebook installs them only with that signature. A notebook with autosync on
# (one time: .\node.cmd autosync user@laptop) checks every 15 s, installs it and reports how it went
# through the laptop's gate; this script waits for that and shows what the notebook said.
#
# v18 hardening: every node runs strict trust (it talks only to the other two, listed by id), the
# phone adopts AI placement decisions only from the laptop (--advisor), and the notebook's sync key
# is locked to a gate on the laptop that serves the staged build and nothing else.
#
# v19: the model stays loaded in llama.cpp's llama-server (built here and on the laptop when it is
# missing; the Windows release of llama.cpp ships it), and every node answers OpenAI's chat API on
# loopback: base URL http://127.0.0.1:3005/v1, any API key, model "harmony".
#
#   bash mesh_upgrade.sh [user@laptop-ip]        default: joe@192.168.1.192
#   SKIP_TESTS=1 bash mesh_upgrade.sh            skip `cargo test` on the phone
#   LAPTOP_TIER=standard|light bash mesh_upgrade.sh   laptop model (default: kept; standard if the 3B file is there)
#   NOTEBOOK_ID=<64 hex> bash mesh_upgrade.sh    the notebook's id, if this script cannot find it
#   TRUST=tofu bash mesh_upgrade.sh              keep trust-on-first-use (not recommended)
#
# Needs in ~/storage/downloads (tap the cards in the chat): p2p_main_piggyback_v19.rs, test_harmony.sh, node.sh,
# and node.ps1 when there is a Windows notebook.
# Android saves re-downloads as name-2, name-3…; this script always takes the newest.
# Stops before touching either node if a file is the wrong version or a build/test fails.
set -euo pipefail

LAPTOP=${1:-joe@192.168.1.192}
LIP=${LAPTOP#*@}
GW=$HOME/harmony_gateway
DL=$HOME/storage/downloads
MARK='piggyback propagation'
ROT='struct IdentityLock'     # automatic port rotation + identity lock that works on Android
V9='fn issue_placement'      # AI placement decisions + /ui dashboard
V10='async fn begin_draining' # graceful startup and shutdown
V11='const MAX_ADVISORY_PROMPT_BYTES' # the operator's note ranks above headroom; greedy advisories
V12='fn post_shutdown'        # runs on Windows too: thermal zones, graceful stop over the API
V13='fn advisory_retry_due'   # a directive that arrives while Llama is busy is advised once it is free
V14='fn reading_choice'       # Llama reads the note (which devices it spares or asks for); the node ranks
V15='fn note_names'           # ... device by device, by name (name=AVOID|USE|ANY), no letters
V16='fn mentioned_names'      # ... only the devices the note names, found by the node; no example answers
V17='fn device_evidence'      # ... the node quotes what the note says about each; the model judges each quote
V18='fn verify_update_dir'    # hardening: strict trust lists, --advisor, signed Windows builds
V19='fn post_chat_completions' # the model kept loaded in llama-server; OpenAI chat API on loopback
BUILD=harmony-v19            # what /health must report after the restart
LOGF=$HOME/mesh_upgrade.log
G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' C=$'\e[36m' N=$'\e[0m'
step() { printf '\n%s== %s ==%s\n' "$C" "$*" "$N"; }
ok()   { printf '%sOK%s   %s\n' "$G" "$N" "$*"; }
warn() { printf '%sWARN%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%sSTOP%s %s\n' "$R" "$N" "$*"; exit 1; }
PPORT=3005
health() { curl -s --max-time 3 "http://127.0.0.1:$PPORT/health" 2>/dev/null || true; }
# the port a node's log says it listens on (it rotates off 3005 when something else holds it)
logport() { sed 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null | grep -oE 'mesh API on http://[^ ]+' | tail -n 1 | grep -oE '[0-9]+$' || true; }
# rustc >= 1.82 ?
rust_ok() { awk '{ split($2, v, "."); exit !(v[1] > 1 || (v[1] == 1 && v[2] >= 82)) }' <<<"$1"; }
# the last line of input that is a node id
idof() { { grep -oE '^[0-9a-f]{64}$' || true; } | tail -n 1; }
: > "$LOGF"

# ------------------------------------------------------------------ 1. files
step "1/7 downloaded files"
for b in curl jq ssh scp cargo; do command -v "$b" >/dev/null || die "missing $b (pkg install curl jq openssh rust)"; done
# newest file named NAME* in Downloads, else anywhere in shared storage (apps save to subfolders)
newest() {
  local f
  f=$(ls -t "$DL"/"$1"* 2>/dev/null | head -n 1 || true)
  [ -n "$f" ] || f=$(find "$HOME/storage/shared/" -maxdepth 4 -type f -name "$1*" -printf '%T@\t%p\n' 2>/dev/null \
                     | sort -rn | head -n 1 | cut -f2- || true)
  printf '%s' "$f"
}
NEW=$(newest p2p_main_piggyback)
[ -n "$NEW" ] || die "p2p_main_piggyback.rs not found on this phone: download it from the chat, then rerun"
grep -q "$MARK" "$NEW" || die "$(basename "$NEW") is not the piggyback build"
for v in "$ROT" "$V9" "$V10" "$V11" "$V12" "$V13" "$V14" "$V15" "$V16" "$V17" "$V18" "$V19"; do
  grep -q "$v" "$NEW" || die "$(basename "$NEW") is older than v19: download p2p_main_piggyback_v19.rs"
done
RV=$(rustc --version 2>/dev/null || echo "rustc 0.0")
rust_ok "$RV" || die "$RV is too old for this build (needs 1.82+): pkg upgrade rust, then rerun"
ok "source: $(basename "$NEW") ($(( $(wc -c < "$NEW") / 1024 )) KB)"
TH=$(newest test_harmony)
# the tests must match the build: an older script checks things this build no longer does
{ [ -n "$TH" ] && grep -q 'openai (v19)' "$TH"; } \
  || die "the newest test_harmony.sh in Downloads is older than this build's tests: download it from the chat, then rerun"
cp "$TH" "$HOME/test_harmony.sh"; ok "test_harmony.sh ($(grep -m1 '^HV=' "$TH" | cut -d= -f2)) installed"
# node.sh: the graceful start/stop script, installed on both devices
NS=""
for f in $(ls -t "$DL"/node*.sh 2>/dev/null || true); do grep -q 'node.sh — start, stop' "$f" && { NS=$f; break; }; done
[ -n "$NS" ] || die "node.sh not found in Downloads: download it from the chat, then rerun"
cp "$NS" "$HOME/node.sh"; ok "node.sh installed (bash ~/node.sh start|stop|restart|status)"
# node.ps1 for the Windows notebook: staged with each build, so its watcher updates it too
for f in $(ls -t "$DL"/node*.ps1 2>/dev/null || true); do
  grep -q 'node.ps1 - start, stop' "$f" && { cp -f "$f" "$HOME/node.ps1"; break; }
done

# ------------------------------------------------------------------ 2. phone build
step "2/7 build on this phone"
cd "$GW"
grep -q "$MARK" src/main.rs || cp src/main.rs "src/main.rs.pre-piggyback.$(date +%s).bak"
[ "$(sha256sum < "$NEW")" = "$(sha256sum < src/main.rs 2>/dev/null)" ] || cp "$NEW" src/main.rs   # unchanged: no rebuild
if [ "${SKIP_TESTS:-0}" != 1 ]; then
  echo "cargo test --release (a few minutes the first time)…"
  if ! cargo test --release >> "$LOGF" 2>&1; then
    grep -E '^(error|test .* FAILED|---- )|panicked at' -A 3 "$LOGF" | grep -v '^note: run with' | head -n 40
    die "cargo test failed: full output in $LOGF (send me the first error)"
  fi
  grep -E '^test result' "$LOGF" | tail -n 1 | sed 's/^/  /'
fi
if ! cargo build --release >> "$LOGF" 2>&1; then
  grep -E '^error' -A 12 "$LOGF" | head -n 40
  die "cargo build failed: full output in $LOGF (send me the first error)"
fi
ok "phone build ready"
# v19 keeps the model loaded in llama.cpp's llama-server, beside the llama binary the node uses.
# Built once when this llama.cpp checkout lacks it; without it the node loads the model per job.
LBIN=$(grep -s '^HARMONY_LLAMA_BIN=' "$HOME/.harmony/node.env" | tail -n 1 | cut -d= -f2- || true)
[ -n "$LBIN" ] || LBIN=$HOME/llama.cpp/build/bin/llama-completion
LDIR=$(dirname "$LBIN")
if [ -x "$LDIR/llama-server" ]; then
  ok "llama-server present: the model stays loaded between jobs"
elif [ -f "$(dirname "$LDIR")/CMakeCache.txt" ] && command -v cmake >/dev/null; then
  echo "building llama.cpp's llama-server once (several minutes on a phone)…"
  if cmake --build "$(dirname "$LDIR")" -j"$(nproc 2>/dev/null || echo 4)" --target llama-server >> "$LOGF" 2>&1 \
     && [ -x "$LDIR/llama-server" ]; then ok "llama-server built: the model stays loaded between jobs"
  else warn "llama-server did not build (end of $LOGF): this phone keeps loading the model for each job"; fi
else
  warn "no llama.cpp build beside $LBIN: this phone keeps loading the model for each job"
fi

# ------------------------------------------------------------------ 3. ids and trust
# Strict trust lists every device by id. The phone's comes from its own binary and the laptop's
# from the laptop; the notebook's from what it reported through the laptop's sync gate (its key
# authenticates it), else from this phone's peers (label "notebook"), else from the last run.
step "3/7 who is in the mesh (strict trust lists every device by its id)"
mkdir -p "$HOME/.harmony"
IDS=$HOME/.harmony/mesh_ids
p=$(logport "$HOME/p2p.log"); [ -n "$p" ] && PPORT=$p
PHONE_ID=$( (set -a; [ -f "$HOME/.harmony/node.env" ] && . "$HOME/.harmony/node.env"; set +a
             "$GW/target/release/rust_p2p_node" --print-id) 2>/dev/null | idof || true)
[ -n "$PHONE_ID" ] || die "could not read this phone's id (rust_p2p_node --print-id)"
LAPTOP_ID=$(ssh -o ConnectTimeout=8 "$LAPTOP" 'set -a; [ -f ~/.harmony/node.env ] && . ~/.harmony/node.env; set +a
             ~/harmony_gateway/target/release/rust_p2p_node --print-id' 2>/dev/null | idof || true)
[ -n "$LAPTOP_ID" ] || die "could not read the laptop's id over ssh (is ~/harmony_gateway built there?)"
HAS_WIN=0; ssh -o ConnectTimeout=8 "$LAPTOP" '[ -d "$HOME/harmony_win" ]' 2>/dev/null && HAS_WIN=1
NOTEBOOK_ID=${NOTEBOOK_ID:-}; NB_FROM="NOTEBOOK_ID="; NB_ADDR=""
if [ "$HAS_WIN" = 1 ]; then
  if [ -z "$NOTEBOOK_ID" ]; then
    NOTEBOOK_ID=$(ssh "$LAPTOP" 'cat ~/.harmony/notebook.id 2>/dev/null' 2>/dev/null | idof || true)
    NB_FROM="its own report through the laptop's sync gate"
  fi
  # this phone's view: the one peer labelled "notebook" (also where it is, for the gate's from=)
  seen=$(curl -s --max-time 3 "http://127.0.0.1:$PPORT/peers" 2>/dev/null | jq -r --arg a "$PHONE_ID" --arg b "$LAPTOP_ID" \
         '[.[] | select(.label == "notebook" and .id != $a and .id != $b)] | if length == 1 then "\(.[0].id) \(.[0].addr)" else empty end' 2>/dev/null || true)
  if [ -z "$NOTEBOOK_ID" ] && [ -n "$seen" ]; then
    NOTEBOOK_ID=$(idof <<<"${seen%% *}"); NB_FROM="this phone's peers (the one labelled notebook, at ${seen#* })"
  fi
  [ -n "$seen" ] && [ "${seen%% *}" = "$NOTEBOOK_ID" ] && NB_ADDR=${seen#* }
  if [ -z "$NOTEBOOK_ID" ]; then
    NOTEBOOK_ID=$(sed -n 's/^notebook \([0-9a-f]\{64\}\)$/\1/p' "$IDS" 2>/dev/null | idof || true)
    NB_FROM="the last run ($IDS)"
  fi
  NOTEBOOK_ID=$(idof <<<"$NOTEBOOK_ID")
  { [ "$NOTEBOOK_ID" = "$PHONE_ID" ] || [ "$NOTEBOOK_ID" = "$LAPTOP_ID" ]; } && die "the notebook's id ($NB_FROM) is another device's"
fi
MODE=${TRUST:-strict}
case $MODE in strict|tofu) ;; *) die "TRUST must be strict or tofu";; esac
if [ "$MODE" = strict ] && [ "$HAS_WIN" = 1 ] && [ -z "$NOTEBOOK_ID" ]; then
  warn "strict trust needs the notebook's id, and it is not known yet: staying on TOFU this run."
  warn "Wake the notebook so it shows on gossip, or rerun with NOTEBOOK_ID=<id from .\\node.cmd status there>."
  MODE=tofu
fi
PHONE_TRUST=$LAPTOP_ID LAPTOP_TRUST=$PHONE_ID NB_TRUST="$PHONE_ID,$LAPTOP_ID"
if [ -n "$NOTEBOOK_ID" ]; then PHONE_TRUST="$PHONE_TRUST,$NOTEBOOK_ID"; LAPTOP_TRUST="$LAPTOP_TRUST,$NOTEBOOK_ID"; fi
{ echo "phone $PHONE_ID"; echo "laptop $LAPTOP_ID"; [ -n "$NOTEBOOK_ID" ] && echo "notebook $NOTEBOOK_ID"; true; } > "$IDS"
ok "phone ${PHONE_ID:0:12}…, laptop ${LAPTOP_ID:0:12}…${NOTEBOOK_ID:+, notebook ${NOTEBOOK_ID:0:12}…}: $MODE trust"
case $NB_FROM in
  "this phone's peers"*) warn "the notebook's id came from $NB_FROM: compare ${NOTEBOOK_ID:0:12} with .\\node.cmd status on the notebook";;
  *) [ -n "$NOTEBOOK_ID" ] && echo "     notebook id from $NB_FROM";;
esac

# ------------------------------------------------------------------ 4. phone restart
step "4/7 restart this phone's node (graceful)"
# settings for node.sh: seed = the laptop; trust = the other two; other lines already in the file are kept
set_env() { local f=$1; touch "$f"; { grep -v "^$2=" "$f" || true; } > "$f.tmp"; echo "$2=$3" >> "$f.tmp"; mv "$f.tmp" "$f"; }
set_env "$HOME/.harmony/node.env" HARMONY_PEERS "$LIP:3005"
set_env "$HOME/.harmony/node.env" HARMONY_TRUST_MODE "$MODE"
set_env "$HOME/.harmony/node.env" HARMONY_TRUST "$PHONE_TRUST"
set_env "$HOME/.harmony/node.env" HARMONY_ADVISOR "$LAPTOP_ID"
[ -n "${HARMONY_MOCK_TEMP:-}" ] && warn "HARMONY_MOCK_TEMP=$HARMONY_MOCK_TEMP is set in this shell; starting with the real sensor anyway"
env -u HARMONY_MOCK_TEMP bash "$HOME/node.sh" restart || die "the phone node did not start: bash ~/node.sh status; tail ~/p2p.log"
p=$(logport "$HOME/p2p.log"); [ -n "$p" ] && PPORT=$p
H=$(health)
[ "$(jq -r '.build // empty' <<<"$H")" = "$BUILD" ] \
  || die "the node answering on :$PPORT is not $BUILD (it reports: $(jq -r '.build // "an older build"' <<<"$H")). bash ~/node.sh status"
PHONE=$(jq -r '.node // empty' <<<"$H")
[ ${#PHONE} -eq 64 ] || die "could not read this phone's id from /health"
[ "$PHONE" = "$PHONE_ID" ] || die "the node runs as ${PHONE:0:12}…, but --print-id said ${PHONE_ID:0:12}…: two identity directories? (HARMONY_DATA_DIR / HARMONY_NODE_NAME)"
[ "$(jq -r '.trust.mode // empty' <<<"$H")" = "$MODE" ] || die "the phone node is not on $MODE trust: bash ~/node.sh status; grep TRUST ~/.harmony/node.env"
[ "$PPORT" = 3005 ] || warn "3005 is held by something else; this node rotated to :$PPORT"
ok "phone node ${PHONE:0:12}… on :$PPORT: $BUILD, $(jq -r .state <<<"$H"), $MODE trust ($(jq -r .trust.trusted <<<"$H") listed), decisions from the laptop"
# the model loads in the background after a start; wait for it (up to a minute) and say how it runs
engine_line() { jq -r '.engine | "\(.state)\(if .load_ms then " (loaded in \(.load_ms / 100 | round / 10) s)" else "" end)\(if (.detail // "") != "" then ": \(.detail)" else "" end)"' <<<"$1" 2>/dev/null; }
for _ in $(seq 30); do case $(health | jq -r '.engine.state // empty') in loading|unloaded) sleep 2;; *) break;; esac; done
H=$(health)
case $(jq -r '.engine.state // empty' <<<"$H") in
  ready) ok "phone: model kept loaded in llama-server, $(engine_line "$H")";;
  off)   echo "     phone: --llama-server off, the model loads for each job";;
  *)     warn "phone: model not kept loaded ($(engine_line "$H")); jobs load it each time";;
esac

# ------------------------------------------------------------------ 5. laptop
step "5/7 laptop $LAPTOP: copy, build, restart with --cmd-allow ${PHONE:0:12}…"
MYIP=$(ssh -o ConnectTimeout=8 "$LAPTOP" 'echo ${SSH_CLIENT%% *}') || die "cannot ssh to $LAPTOP"
[ -n "$MYIP" ] || die "could not learn this phone's IP from $LAPTOP"
[ "$(ssh "$LAPTOP" 'sha256sum < ~/harmony_gateway/src/main.rs' 2>/dev/null)" = "$(sha256sum < src/main.rs)" ] \
  || scp -q src/main.rs "$LAPTOP:harmony_gateway/src/main.rs"
scp -q "$HOME/node.sh" "$LAPTOP:node.sh"
# the sync gate: all the Windows notebook's key may do on the laptop (installed even without a notebook)
ssh "$LAPTOP" 'mkdir -p ~/.harmony && cat > ~/.harmony/sync_gate.sh.new && chmod 755 ~/.harmony/sync_gate.sh.new && mv -f ~/.harmony/sync_gate.sh.new ~/.harmony/sync_gate.sh' <<'GATE' || die "could not install the sync gate on the laptop"
#!/bin/sh
# sync_gate.sh (harmony-v19): everything the Windows notebook's sync key may do on this laptop.
# mesh_upgrade.sh installs it as ~/.harmony/sync_gate.sh. The key's line in ~/.ssh/authorized_keys,
#   restrict,from="192.168.1.*",command="/home/USER/.harmony/sync_gate.sh --forced" ssh-ed25519 AAAA... harmony-sync@PC
# makes sshd run this, whatever the notebook asks, with the request in SSH_ORIGINAL_COMMAND.
#
#   for the notebook:  ping | status | files | get NAME | deployed TAG [NODE_ID] | report TEXT
#   from a full login: enroll ssh-ed25519 KEY harmony-sync@PC | restrict-keys [FROM]
#
# The notebook can read the staged build in ~/harmony_win_update, say what it installed, and leave
# one short line on how its syncs go (~/.harmony/notebook.status, which mesh_upgrade.sh shows). It
# cannot read anything else, write anything else, or run a command.
set -u
umask 077
D=$HOME/harmony_win_update
IDF=$HOME/.harmony/notebook.id
RPT=$HOME/.harmony/notebook.status
GATE=$HOME/.harmony/sync_gate.sh
AK=$HOME/.ssh/authorized_keys
refuse() { echo "sync gate: refused: $*" >&2; exit 1; }
name_ok() {
  case $1 in ''|.*|*[!A-Za-z0-9._-]*|*..*) return 1;; esac
  [ ${#1} -le 64 ]
}
tag_ok() {
  case $1 in harmony-v[0-9]*) ;; *) return 1;; esac
  case ${1#harmony-v} in *[!0-9]*) return 1;; esac
  [ ${#1} -le 16 ]
}
id_ok() { case $1 in *[!0-9a-f]*) return 1;; esac; [ ${#1} -eq 64 ]; }
# the caller's /24 as an authorized_keys from= pattern, or * when it cannot be told
lan() {
  ip=${SSH_CLIENT:-}; ip=${ip%% *}
  case $ip in [0-9]*.[0-9]*.[0-9]*.[0-9]*) echo "${ip%.*}.*";; *) echo '*';; esac
}

forced=0
if [ "${1:-}" = --forced ]; then
  # through the key: the request is the client's command line, split into words, never run
  forced=1
  set -f
  # shellcheck disable=SC2086
  set -- ${SSH_ORIGINAL_COMMAND:-}
  set +f
  case ${1:-} in */sync_gate.sh|sync_gate.sh) shift;; esac
fi
verb=${1:-}
[ $# -gt 0 ] && shift

case $verb in
  ping)
    echo "harmony-sync-gate 1";;
  status)
    [ -f "$D/BUILD" ] && printf 'BUILD:%s\n' "$(head -c 64 "$D/BUILD" | tr -cd 'A-Za-z0-9.-')"
    [ -f "$D/DEPLOYED" ] && printf 'DEPLOYED:%s\n' "$(head -c 64 "$D/DEPLOYED" | tr -cd 'A-Za-z0-9.-')"
    [ -f "$IDF" ] && printf 'NODE:%s\n' "$(head -c 64 "$IDF" | tr -cd '0-9a-f')"
    exit 0;;
  files)
    [ -d "$D" ] || refuse "nothing staged"
    find "$D" -mindepth 1 -maxdepth 1 -type f -printf '%s %f\n' | while read -r size name; do
      [ "$name" = DEPLOYED ] && continue
      name_ok "$name" && printf '%s %s\n' "$size" "$name"
    done
    exit 0;;
  get)
    n=${1:-}
    name_ok "$n" || refuse "bad file name"
    [ "$n" != DEPLOYED ] || refuse "DEPLOYED is not part of the build"
    { [ -f "$D/$n" ] && [ ! -L "$D/$n" ]; } || refuse "no staged file $n"
    base64 -w 0 < "$D/$n"; echo;;
  deployed)
    t=${1:-}
    tag_ok "$t" || refuse "bad build tag"
    { [ -d "$D" ] && [ ! -L "$D" ]; } || refuse "nothing staged"
    if [ -n "${2:-}" ]; then id_ok "$2" || refuse "bad node id"; fi
    printf '%s\n' "$t" > "$D/DEPLOYED" || refuse "cannot record DEPLOYED"
    if [ -n "${2:-}" ]; then mkdir -p "${IDF%/*}" && printf '%s\n' "$2" > "$IDF"; fi
    echo "recorded $t";;
  report)
    # how the notebook's last sync went: one line of plain ASCII, at most 300 bytes, with the
    # time it came; kept as text, never run
    msg=$(printf '%s' "$*" | tr -c "A-Za-z0-9 .,:;()/+=_@%?!'-" ' ' | tr -s ' ' | head -c 300)
    case $msg in ''|' ') refuse "empty report";; esac
    { mkdir -p "${RPT%/*}" && printf '%s %s\n' "$(date +%s)" "$msg" > "$RPT.$$" && mv -f "$RPT.$$" "$RPT"; } \
      || refuse "cannot record the report"
    echo "noted";;
  enroll)
    [ "$forced" = 0 ] || refuse "enroll needs a full login"
    [ "${1:-}" = ssh-ed25519 ] || refuse "expected an ssh-ed25519 key"
    key=${2:-}; comment=${3:-}
    case $key in ''|*[!A-Za-z0-9+/=]*) refuse "bad key";; esac
    case $comment in harmony-sync@?*) ;; *) refuse "expected a harmony-sync@PC comment";; esac
    name_ok "${comment#harmony-sync@}" || refuse "bad comment"
    from=$(lan)
    { mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh" && touch "$AK"; } || refuse "cannot write $AK"
    { { grep -vF " $key " "$AK" || true
        printf 'restrict,from="%s",command="%s --forced" ssh-ed25519 %s %s\n' "$from" "$GATE" "$key" "$comment"
      } > "$AK.gate.$$" && chmod 600 "$AK.gate.$$" && mv -f "$AK.gate.$$" "$AK"; } || refuse "could not update $AK"
    echo "enrolled $comment: it can use this gate only, from $from";;
  restrict-keys)
    [ "$forced" = 0 ] || refuse "restrict-keys needs a full login"
    from=${1:-$(lan)}
    case $from in ''|*[!0-9.*]*) refuse "bad from pattern";; esac
    [ -f "$AK" ] || { echo "restricted 0 harmony-sync key(s): no $AK"; exit 0; }
    n=0
    { while IFS= read -r line || [ -n "$line" ]; do
        case $line in
          *ssh-ed25519\ *harmony-sync@*)
            printf 'restrict,from="%s",command="%s --forced" ssh-ed25519 %s\n' "$from" "$GATE" "${line#*ssh-ed25519 }"
            n=$((n + 1));;
          *) printf '%s\n' "$line";;
        esac
      done < "$AK" > "$AK.gate.$$" && chmod 600 "$AK.gate.$$" && mv -f "$AK.gate.$$" "$AK"; } || refuse "could not update $AK"
    echo "restricted $n harmony-sync key(s): this gate only, from $from";;
  *)
    refuse "unknown request${verb:+ \"$verb\"}";;
esac
GATE
echo "cargo build --release on the laptop…"
ssh "$LAPTOP" 'set -eo pipefail; source "$HOME/.cargo/env"; cd ~/harmony_gateway
  grep -q "fn post_chat_completions" src/main.rs
  v=$(rustc --version); echo "$v"
  echo "$v" | awk "{ split(\$2, v, \".\"); exit !(v[1] > 1 || (v[1] == 1 && v[2] >= 82)) }" || rustup update stable
  cargo build --release 2>&1 | tail -n 3' || die "laptop build failed (output above)"
# laptop settings for node.sh, then a graceful restart there
# (ssh joins the arguments into one command line, so an empty one vanishes: the optional tier goes last)
ssh "$LAPTOP" bash -s -- "$MYIP:$PPORT" "$PHONE" "$MODE" "$LAPTOP_TRUST" "${LAPTOP_TIER:-}" <<'REMOTE' || die "the laptop node did not start: ssh $LAPTOP 'bash ~/node.sh status'"
set -e
f=$HOME/.harmony/node.env; mkdir -p "${f%/*}"; touch "$f"
set_env() { { grep -v "^$1=" "$f" || true; } > "$f.tmp"; echo "$1=$2" >> "$f.tmp"; mv "$f.tmp" "$f"; }
lb=$HOME/llama.cpp/build/bin/llama-completion; [ -x "$lb" ] || lb=$HOME/llama.cpp/build/bin/llama-cli
set_env HARMONY_PEERS "$1"
set_env HARMONY_CMD_ALLOW "$2"
set_env HARMONY_LLAMA_BIN "$lb"
# v19 keeps the model loaded in llama.cpp's llama-server beside $lb: built once when missing
ld=$(dirname "$lb")
if [ ! -x "$ld/llama-server" ] && [ -f "$(dirname "$ld")/CMakeCache.txt" ] && command -v cmake >/dev/null; then
  echo "building llama.cpp's llama-server once on the laptop…"
  cmake --build "$(dirname "$ld")" -j"$(nproc)" --target llama-server > "$HOME/llama_server_build.log" 2>&1 \
    || echo "llama-server did not build (~/llama_server_build.log): the laptop keeps loading the model for each job"
fi
set_env HARMONY_TRUST_MODE "$3"
set_env HARMONY_TRUST "$4"
tier=${5:-}
if [ -z "$tier" ] && ! grep -q '^HARMONY_MODEL_TIER=' "$f" && [ -e "$HOME/harmony_gateway/llama-3.2-3b-instruct.gguf" ]; then tier=standard; fi
if [ -n "$tier" ]; then set_env HARMONY_MODEL_TIER "$tier"; fi
env -u HARMONY_MOCK_TEMP bash "$HOME/node.sh" restart
REMOTE
LPORT=$(ssh "$LAPTOP" "sed 's/\x1b\[[0-9;]*m//g' ~/p2p.log | grep -oE 'mesh API on http://[^ ]+' | tail -n 1 | grep -oE '[0-9]+\$'" 2>/dev/null || true)
LPORT=${LPORT:-3005}
LH=$(ssh "$LAPTOP" "curl -s --max-time 3 http://127.0.0.1:$LPORT/health" 2>/dev/null || true)
[ "$(jq -r '.build // empty' <<<"$LH" 2>/dev/null)" = "$BUILD" ] \
  || die "the laptop node answering on :$LPORT is not $BUILD: ssh $LAPTOP 'bash ~/node.sh status'"
[ "$(jq -r '.node // empty' <<<"$LH")" = "$LAPTOP_ID" ] || die "the laptop node's id is not the one listed in the trust lists (${LAPTOP_ID:0:12}…)"
[ "$(jq -r '.trust.mode // empty' <<<"$LH")" = "$MODE" ] || die "the laptop node is not on $MODE trust: ssh $LAPTOP 'grep TRUST ~/.harmony/node.env'"
[ "$LPORT" = 3005 ] || warn "laptop rotated to :$LPORT (3005 was taken there); the phone learns that from the handshake"
[ "$(jq -r '.llama_bin_found' <<<"$LH")" = true ] || warn "laptop reports llama_bin_found=false: advisories will fail there"
[ "$(jq -r '.model_file_present' <<<"$LH")" = false ] && warn "laptop has no model file for tier $(jq -r '.tier' <<<"$LH"): $(jq -r '.model' <<<"$LH")"
ok "laptop node ${LAPTOP_ID:0:12}… on :$LPORT: $BUILD, $(jq -r .tier <<<"$LH"), $MODE trust, accepting directives from ${PHONE:0:12}…"
for _ in $(seq 30); do
  LH=$(ssh "$LAPTOP" "curl -s --max-time 3 http://127.0.0.1:$LPORT/health" 2>/dev/null || true)
  case $(jq -r '.engine.state // empty' <<<"$LH" 2>/dev/null) in loading|unloaded) sleep 2;; *) break;; esac
done
case $(jq -r '.engine.state // empty' <<<"$LH" 2>/dev/null) in
  ready) ok "laptop: model kept loaded in llama-server, $(engine_line "$LH")";;
  off)   echo "     laptop: --llama-server off, the model loads for each job";;
  *)     warn "laptop: model not kept loaded ($(engine_line "$LH")); jobs load it each time";;
esac

# ------------------------------------------------------------------ 6. mesh
step "6/7 mesh: waiting for the laptop's vitals to arrive on gossip"
got=""
for _ in $(seq 45); do
  got=$(curl -s --max-time 3 "http://127.0.0.1:$PPORT/peers" 2>/dev/null \
        | jq -r '.[] | select(.thermal_c != null) | "\(.id[0:12]) @ \(.addr)  \(.thermal_c) °C / \(.max_temp)  \(.tier)"' 2>/dev/null || true)
  [ -n "$got" ] && break
  sleep 2
done
if [ -n "$got" ]; then ok "piggybacked vitals: $got"
else warn "no peer vitals yet after 90 s (gossip may be slower); the relay test waits longer"; fi

# ------------------------------------------------------------------ 7. Windows notebook
step "7/7 laptop: the same build for the Windows notebook, signed by this phone"
NB_FIRST="" GATE_PS1=0
if ssh "$LAPTOP" 'command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 && [ -d "$HOME/harmony_win" ]'; then
  echo "cargo build --release --target x86_64-pc-windows-gnu on the laptop…"
  if ssh "$LAPTOP" bash -s -- "$BUILD" <<'REMOTE'
set -eo pipefail
source "$HOME/.cargo/env"
cd ~/harmony_gateway
t=x86_64-pc-windows-gnu
if ! cargo build --release --target "$t" > ~/win_build.log 2>&1; then
  grep -E '^error' -A 12 ~/win_build.log | head -n 30; exit 4
fi
exe=target/$t/release/rust_p2p_node.exe
grep -aqF "$1" "$exe" || { echo "built, but $exe is not $1"; exit 5; }
N=$HOME/harmony_win_update.new
rm -rf "$N" && mkdir -p "$N" && cp -f "$exe" "$N/"
# DLLs the .exe imports that Windows does not ship (MinGW's runtime, if it was linked dynamically)
for dll in $(x86_64-w64-mingw32-objdump -p "$exe" | sed -n 's/^[[:space:]]*DLL Name: //p'); do
  f=$(x86_64-w64-mingw32-gcc -print-file-name="$dll")
  if [ "$f" != "$dll" ] && [ -f "$f" ]; then cp -f "$f" "$N/"; fi
done
REMOTE
  then
    if grep -q 'function Invoke-Gate' "$HOME/node.ps1" 2>/dev/null; then
      scp -q "$HOME/node.ps1" "$LAPTOP:harmony_win_update.new/node.ps1"; GATE_PS1=1
      grep -q 'function Send-SyncReport' "$HOME/node.ps1" \
        || warn "node.ps1 on this phone predates v19.1 (checks every minute, sends no reports): download node.ps1 from the chat and rerun"
    elif grep -q 'function Sync-Node' "$HOME/node.ps1" 2>/dev/null; then
      warn "node.ps1 on this phone predates v18 (no sync gate): not staged, and the notebook's key stays unrestricted; download node.ps1 from the chat"
    else
      warn "no node.ps1 with autosync on this phone: download node.ps1 from the chat (the notebook keeps its own)"
    fi
    # mesh settings for the notebook; node.ps1 takes only these keys, and they are signed with the build
    ssh "$LAPTOP" "cat > ~/harmony_win_update.new/mesh.env && echo $BUILD > ~/harmony_win_update.new/BUILD" <<EOF || die "could not write mesh.env on the laptop"
# mesh settings from mesh_upgrade.sh, signed with this build; node.ps1 applies these keys only
HARMONY_TRUST_MODE=$MODE
HARMONY_TRUST=$NB_TRUST
HARMONY_ADVISOR=$LAPTOP_ID
UPDATE_SIGNER=$PHONE_ID
EOF
    # this phone signs exactly the staged files; the laptop only built them
    SIGN=$HOME/.harmony/winsign; rm -rf "$SIGN"
    scp -q -r "$LAPTOP:harmony_win_update.new" "$SIGN" || die "could not fetch the staged build to sign it"
    out=$( (set -a; [ -f "$HOME/.harmony/node.env" ] && . "$HOME/.harmony/node.env"; set +a
            "$GW/target/release/rust_p2p_node" --sign-update "$SIGN") 2>&1 | tail -n 1 || true)
    case $out in signed*) ;; *) die "signing the notebook's build failed: $out";; esac
    scp -q "$SIGN/MANIFEST" "$SIGN/MANIFEST.sig" "$LAPTOP:harmony_win_update.new/" || die "could not copy the signature to the laptop"
    rm -rf "$SIGN"
    v=$(ssh "$LAPTOP" "~/harmony_gateway/target/release/rust_p2p_node --verify-update ~/harmony_win_update.new --update-signer $PHONE_ID" 2>&1 | tail -n 1 || true)
    case $v in OK*) ok "notebook build signed by this phone and verified on the laptop (${v#OK })";;
               *) die "the staged notebook build does not verify on the laptop: $v";; esac
    # Has the notebook reported a build before? Then its watcher is on and this run waits for it.
    WATCHED=$(ssh "$LAPTOP" 'cat ~/harmony_win_update/DEPLOYED 2>/dev/null' || true)
    # one rename, so a watcher never copies half a build
    ssh "$LAPTOP" "rm -rf ~/harmony_win_update && mv ~/harmony_win_update.new ~/harmony_win_update"
    staged=$SECONDS
    ok "rust_p2p_node.exe ($BUILD) staged on the laptop in ~/harmony_win_update"
    # the notebook's last word on its syncs, through the gate (node.ps1 v19.1+): "AGE_S TEXT", or nothing
    nb_said() { ssh "$LAPTOP" 'f=~/.harmony/notebook.status; [ -f "$f" ] && read -r t s < "$f" && echo "$(( $(date +%s) - t )) $s"' 2>/dev/null || true; }
    # ... and only if it came after this build was staged
    nb_fresh() { local s; s=$(nb_said); [ -n "$s" ] && [ "${s%% *}" -le $((SECONDS - staged + 2)) ] && printf '%s' "$s"; true; }
    nb_first() { printf 'cd ~\\harmony; scp "%s:harmony_win_update/node.ps1" .; .\\node.cmd autosync %s' "$LAPTOP" "$LAPTOP"; }
    if [ -n "$WATCHED" ]; then
      echo "waiting for the notebook to install it (its watcher checks the laptop every 15 s)…"
      dep="" last="" t0=$SECONDS
      while [ $((SECONDS - t0)) -lt "${WIN_WAIT:-180}" ]; do
        dep=$(ssh "$LAPTOP" 'cat ~/harmony_win_update/DEPLOYED 2>/dev/null' || true)
        [ "$dep" = "$BUILD" ] && break
        # what the notebook says about this build; a refusal does not change by waiting
        said=$(nb_fresh)
        if [ -n "$said" ] && [ "${said#* }" != "$last" ]; then
          last=${said#* }; echo "     notebook: $last"
          case $last in refused*|*"did not start here"*) break;; esac
        fi
        sleep 6
      done
      if [ "$dep" = "$BUILD" ]; then
        ok "notebook: installed $BUILD and restarted on it by itself ($((SECONDS - t0)) s)"
        # a v19.1+ sync reports right after it installs; no report means an older node.ps1 did,
        # and that watcher keeps its older loop (every minute, no reports) until it is restarted
        said=""
        for _ in 1 2 3 4 5; do said=$(nb_fresh); [ -n "$said" ] && break; sleep 2; done
        case ${said:-none} in none|*"watcher here is older"*)
          echo "     its watcher still runs an older node.ps1 (every minute, no reports): restart it once, as below"
          NB_FIRST=$(nb_first);;
        esac
      else
        said=$(nb_said) age=""
        [ -n "$said" ] && age=${said%% *}
        # awake = a peer other than the laptop with fresh vitals on this phone's gossip
        awake=$(curl -s --max-time 3 "http://127.0.0.1:$PPORT/peers" 2>/dev/null | jq -r --arg l "$LIP" \
          '[.[] | select((.addr | startswith($l + ":")) | not) | select(.vitals_age_s != null and .vitals_age_s < 30) | (.label // .id[0:12])] | join(", ")' 2>/dev/null || true)
        if [ -n "$age" ] && [ "$age" -le $((SECONDS - staged + 2)) ]; then
          # its watcher runs (it reported since the staging), and says why the build is not in
          warn "the notebook's watcher runs but has not installed $BUILD; its last sync: ${said#* }"
          case $said in *"watcher here is older"*) NB_FIRST=$(nb_first);; esac
        elif [ -n "$awake" ] && [ -n "$age" ]; then
          warn "the notebook ($awake) is on gossip, but its last sync report is $((age / 60)) min old (\"${said#* }\"): its watcher is not running"
          NB_FIRST=$(nb_first)
        elif [ -n "$awake" ]; then
          warn "the notebook ($awake) is on gossip but has not installed $BUILD in ${WIN_WAIT:-180} s, and has never reported a sync: its watcher is not running, or its node.ps1 predates v19.1 (which reports)"
          NB_FIRST=$(nb_first)
        else
          warn "the notebook has not installed $BUILD in ${WIN_WAIT:-180} s and is not on gossip (asleep or off?): it installs it when it next checks"
          [ -n "$age" ] && echo "     its last sync report, $((age / 60)) min ago: ${said#* }"
        fi
      fi
    else
      NB_FIRST=$(nb_first)
    fi
    # Lock the notebook's key to the gate once the notebook runs a node.ps1 that speaks it (v18+).
    # The notebook also does this itself on its first v18 sync; this covers a key it no longer uses.
    open=$(ssh "$LAPTOP" 'grep "harmony-sync@" ~/.ssh/authorized_keys 2>/dev/null | grep -vc "sync_gate.sh --forced"' 2>/dev/null || true)
    dn=$(ssh "$LAPTOP" 'cat ~/harmony_win_update/DEPLOYED 2>/dev/null' || true); dn=${dn#harmony-v}
    case $dn in ''|*[!0-9]*) dn=0;; esac
    if [ "${open:-0}" = 0 ]; then
      ssh "$LAPTOP" 'grep -q "harmony-sync@" ~/.ssh/authorized_keys 2>/dev/null' && ok "notebook key: locked to the laptop's sync gate"
    elif [ "$GATE_PS1" = 1 ] && [ "$dn" -ge 18 ]; then
      from='*'; [ -n "$NB_ADDR" ] && from="$(cut -d. -f1-3 <<<"${NB_ADDR%:*}").*"
      r=$(ssh "$LAPTOP" "~/.harmony/sync_gate.sh restrict-keys '$from'" 2>&1 | tail -n 1 || true)
      case $r in restricted*) ok "notebook key: $r";; *) warn "could not lock the notebook's key to the gate: $r";; esac
    elif [ "$GATE_PS1" = 1 ]; then
      echo "     the notebook's key still opens a shell on the laptop until the notebook runs v18 (its first v18 sync locks it)"
    else
      warn "the notebook's key still opens a shell on the laptop: stage node.ps1 v18 (download it from the chat) and rerun"
    fi
  else
    warn "the Windows build failed (output above; full log ~/win_build.log on the laptop): the notebook keeps its current build"
  fi
else
  echo "     no Windows node was set up from this laptop (win_node.sh): skipped"
fi

echo
echo "Trust: $MODE. Phone and laptop talk only to ${NOTEBOOK_ID:+the notebook and }each other; the phone takes AI decisions only from the laptop."
[ "$MODE" = tofu ] && echo "       (TOFU: any device on this network can still join; rerun once the notebook's id is known)"
echo "Dashboard: open http://127.0.0.1:$PPORT/ui in this phone's browser"
echo "Start/stop either node gracefully: bash ~/node.sh start|stop|restart|status"
if [ -n "$NB_FIRST" ]; then
  echo
  echo "Windows notebook: in PowerShell (a normal window) run this line. It turns autosync on (or restarts"
  echo "its watcher), asks the laptop's password once or twice, and installs $BUILD; from then on the notebook"
  echo "installs every build this script makes by itself, so the three devices stay on one build:"
  echo "  $NB_FIRST"
  echo
fi
echo "OpenAI API on every node (loopback): base URL http://127.0.0.1:$PPORT/v1, any API key, model harmony. Try:"
echo "  curl -s http://127.0.0.1:$PPORT/v1/chat/completions -H 'content-type: application/json' -d '{\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}' | jq -r '.choices[0].message.content, .harmony.device'"
echo "Next:  bash ~/test_harmony.sh openai                        (v19: the OpenAI API and the kept-loaded model, ~2 min)"
echo "       PEER_SSH=$LAPTOP bash ~/test_harmony.sh harden   (the v18 hardening, ~2 min)"
echo "       PEER_SSH=$LAPTOP bash ~/test_harmony.sh mesh     (the whole entry, ~14 min)"
