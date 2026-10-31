#!/usr/bin/env bash
# publish_repo.sh — publish the Harmony nodes as a clean public GitHub repo, from the phone (Termux).
#
#   bash publish_repo.sh [repo-name]        default: harmony-thermal-offload
#   DRY_RUN=1 bash publish_repo.sh          build + scan + list files, publish nothing
#   PUBLISH_DIRS="harmony_gateway harmony_cew_node" bash publish_repo.sh   widen the scope
#
# Scope: the hackathon entry only (dynamic thermal offload + piggyback propagation under AI control),
# i.e. ~/harmony_gateway (rust_p2p_node) by default.
# Builds ~/<repo-name> from SOURCE ONLY (Cargo.toml/lock, *.rs, *.gbnf, *.sh, *.md) — never keys,
# certs, CRLs, tokens, models, target/, *.bak, binaries, or old .git history. Aborts if any private key,
# your enrollment token, or a >50 MB file shows up. Shows every file and asks before anything goes public.
# Rerun after code changes: it re-syncs, commits, and pushes the update.
set -euo pipefail

NAME=${1:-harmony-thermal-offload}
OUT=$HOME/$NAME
read -r -a DIRS <<<"${PUBLISH_DIRS:-harmony_gateway}"
CEW=$HOME/harmony_cew_node GW=$HOME/harmony_gateway   # secret sources to scan against
DESC="Llama-advised dynamic thermal offloading and piggyback propagation across a device mesh"
G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' C=$'\e[36m' N=$'\e[0m'
step() { printf '\n%s== %s ==%s\n' "$C" "$*" "$N"; }
ok()   { printf '%sOK%s   %s\n' "$G" "$N" "$*"; }
warn() { printf '%sWARN%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%sSTOP%s %s\n' "$R" "$N" "$*"; exit 1; }

# ------------------------------------------------------------------ preflight
step "preflight"
for b in git find grep cp; do command -v "$b" >/dev/null || die "missing $b -> pkg install git findutils coreutils grep"; done
[ "${DRY_RUN:-0}" = 1 ] || command -v gh >/dev/null || die "missing gh -> pkg install gh"
for d in "${DIRS[@]}"; do [ -d "$HOME/$d/src" ] || die "expected ~/$d/src"; done
case $NAME in *[!A-Za-z0-9._-]*|'') die "repo name may use letters, digits, . _ - only";; esac
ok "sources: ${DIRS[*]}  ->  ~/$NAME"

# ------------------------------------------------------------------ github login (before commit: sets author)
if [ "${DRY_RUN:-0}" != 1 ]; then
  step "github login"
  if ! gh auth status -h github.com >/dev/null 2>&1; then
    echo "A one-time code will appear; enter it at github.com/login/device"
    BROWSER=${BROWSER:-termux-open-url} gh auth login -h github.com -p https -w
  fi
  gh auth setup-git -h github.com
  LOGIN=$(gh api user -q .login); GHID=$(gh api user -q .id)
  ok "signed in as $LOGIN"
fi

# ------------------------------------------------------------------ stage (whitelist)
step "copy source only"
mkdir -p "$OUT"; cd "$OUT"
[ -d .git ] || git init -q -b main
# resync: drop previous copies (tracked or left over from an aborted run) of the dirs this script owns
git rm -r -q -f --ignore-unmatch -- harmony_gateway harmony_cew_node scripts >/dev/null 2>&1 || true
git clean -fdq -- harmony_gateway harmony_cew_node scripts 2>/dev/null || true
stage() {  # <src> <dest-subdir>
  mkdir -p "$OUT/$2"
  (cd "$1" && find . \( -name target -o -name .git -o -name node_modules -o -name '.harmony*' \) -prune -o -type f \
      \( -name '*.rs' -o -name '*.toml' -o -name Cargo.lock -o -name '*.gbnf' -o -name '*.md' -o -name '*.sh' \) \
      ! -name '*.bak' ! -name '*.bak.*' ! -name '*.orig' -print0 | xargs -0 -r cp --parents -t "$OUT/$2")
}
for d in "${DIRS[@]}"; do stage "$HOME/$d" "$d"; done
mkdir -p scripts
[ -f "$HOME/test_harmony.sh" ] && cp "$HOME/test_harmony.sh" scripts/
[ -f "$HOME/node.sh" ] && cp "$HOME/node.sh" scripts/
for f in win_node.sh node.ps1 node.cmd setup_windows.ps1; do [ -f "$HOME/$f" ] && cp "$HOME/$f" scripts/; done
m=$(ls -t "$HOME"/storage/downloads/mesh_upgrade*.sh 2>/dev/null | head -n 1 || true); [ -n "$m" ] && cp "$m" scripts/mesh_upgrade.sh

[ -f .gitignore ] || cat > .gitignore <<'EOF'
# never publish: keys, certificates, revocation lists, tokens, models, builds
target/
*.key
*.pem
*.crt
*.csr
*.srl
*.crl*
.enroll_token
*.gguf
*.bak
llama-cli
llama-completion
*.log
.harmony*/
EOF

[ -f README.md ] || cat > README.md <<'EOF'
# Harmony: AI-controlled thermal offloading and piggyback propagation

Hackathon entry. A mesh of consumer devices (an Android phone in Termux and a Linux laptop) running
Meta **Llama 3.2** Instruct through llama.cpp. When a device gets too hot to generate, its work moves
to a cooler peer instead of failing.

## Dynamic thermal offloading
- Every node reads its SoC temperature (`/sys/class/thermal/thermal_zone0`) and reports it in `/health` as `thermal_c`.
- At or above `--max-temp` (`HARMONY_MAX_TEMP_C`, default 65 °C) a node refuses local LLM runs.
- `POST /infer` with `offload` (default on): if the local node can't serve (too hot, busy, rate limited) and no
  answer succeeded, the request is handed to a peer; the response names it in `offloaded_to`.
- Bad requests are never offloaded, only capacity failures. EMCON mode clamps fan-out to zero.
- Each node picks a model tier from its RAM and cores (`light-1b`, `standard-3b`).

## Piggyback propagation
Nothing here adds a message to the network: it all rides on gossip the mesh already sends.
- **Vitals.** Every gossip ping and pong carries the sender's temperature, thermal limit, busy flag
  and model tier. Each node keeps its peers' latest vitals (`GET /peers`), and offload and fan-out
  ask the coolest idle peers first, skipping any peer already at its own limit.
- **Directives.** `POST /relay` signs a directive with the node's ML-DSA-87 identity key. It rides
  on gossip pings, one per ping; the receiver acknowledges it in the pong that answers that ping,
  so the sender stops carrying it to that peer, and the receiver carries it onward
  (bounded by 8 hops and 10 minutes).
- **Verified at every hop.** Each node checks that the key matches the origin's fingerprint, that
  the signature is valid, and that the origin is in its own `--cmd-allow`, before forwarding or advising.
- **Thermal-aware.** A hot node still relays (relaying is free) but defers its Llama advisory until
  it cools, then retries.
- **Wire-compatible.** Empty fields are omitted, so a plain ping is byte-identical to the previous format.

## AI control: Llama reads the operator's intent, the node places the work, the rules can veto
- A directive in plain language ("the phone's battery is low, run AI jobs on the laptop") reaches
  a peer on gossip. The node finds the devices it names (by `--label`, whole words, any case),
  cuts it into clauses, and quotes for each device the clauses about it. The peer's local Llama
  then labels each quote AVOID (keep jobs off it), USE (run jobs on it) or ANY. A llama.cpp
  grammar writes the whole answer except the labels, so each label is chosen right after the
  words it judges:
  ```
  notebook: "The notebook is overheating in the sun" => AVOID
  phone: "the phone is nearly flat" => AVOID
  ```
  Advisories decode greedily (`--temp 0`): the same note always reads the same way. A note that
  names no device is not sent to the model.
- **The model reads, the node does the arithmetic.** Among the devices below their limit with
  fresh vitals that the note does not spare, the node takes the rules' pick (idle first, most
  headroom) of those it asks to USE, or of all of them when it asks for none.
- **How we got here, on Llama 3.2 3B:** asked to pick a device from temperatures, it picked one
  with less headroom than another (v13); asked for device letters, it inverted the note (v14);
  given example answers, it copied them (v15, 2 of 9 notes); given every named device in one
  line, it carried one device's label to the next (v16, 7 of 9). Quoting the note per device and
  asking only for labels: 13 of 13, including 4 notes added after the prompt was settled (v17).
- The node that ran the model signs the result as a **placement decision** (ML-DSA-87) and it rides
  back across the mesh on gossip. Nodes then send single-answer jobs (`POST /infer` with `fanout:0`)
  to that device, for 10 minutes or until a newer decision replaces it.
- `POST /advise` (loopback, JSON) is a dry run: the device's Llama reads a note exactly as it reads a
  directive and the answer says where jobs would go; nothing is signed or issued.
  `bash scripts/test_harmony.sh reading` runs 13 notes through it.
- **Rules veto.** A pick is used only while that device is below its temperature limit, idle and
  reporting fresh vitals. Otherwise the job goes where the rules put it (run here if cool, else the
  coolest idle peer) and the veto is recorded. The model chooses; the rules keep it safe.
- Each decision records what the rules alone would have picked, so you can see when the AI followed
  them and when it overrode them for a reason they can't see, like a low battery or a meeting.
- A decision is adopted only as the answer to a directive the node holds, and only if this node,
  an `--advisor` or a `--cmd-allow` identity signed it; it lasts at most 10 minutes.
  `"placement":"rules"` in a job ignores decisions.
- Advisory runs are refused at or above `--max-temp`, so a hot device doesn't spend heat on advice;
  it relays the directive anyway and advises once it cools.

## Live dashboard
Open `http://127.0.0.1:3005/ui` on a node (in the phone's browser, or the laptop's). It shows each
device's temperature and headroom, the decision in force and the rules' pick, a mesh map where
directives, acknowledgements, decisions and jobs move along the links, and the event log. You can
send directives and run jobs from it. It is a single self-contained page with no external
resources, served only on loopback; requests whose Host or Origin is not this machine are refused.

## Security
- **Transport:** ML-KEM-1024 (static + ephemeral, so recorded traffic stays safe if a key leaks
  later), ML-DSA-87 identities, HKDF-SHA-384, AES-256-GCM with a key per direction, counter nonces
  and a replay window; frames padded to fixed sizes; the initiator's identity is encrypted in the
  handshake. The handshake is this project's own design and the RustCrypto `ml-kem` / `ml-dsa`
  crates are unaudited, so treat it as research-grade.
- **Who is in the mesh:** `--trust-mode strict` with `--trust <ids>` (`HARMONY_TRUST`): a node
  handshakes with, gossips to and offloads jobs to exactly those identities, inbound and outbound,
  and `/id` and `/hello` answer only private addresses. `tofu` (the default) is for first setup:
  it pins whatever completes a handshake. `scripts/mesh_upgrade.sh` puts all three devices on strict.
- **Who can steer it:** directives need an ML-DSA-87 signature from a `--cmd-allow` identity; AI
  placement decisions need one from this node, an `--advisor` or a `--cmd-allow` identity.
- **Operator API:** loopback only, refusing a Host or Origin that is not this machine (DNS rebinding,
  cross-site pages); the dashboard escapes everything it shows and sends a strict CSP.
- **Windows updates:** the laptop builds the notebook's `.exe`, the phone signs a manifest of the
  staged files (`--sign-update`), and the notebook installs only what verifies against the pinned
  phone id, with the node it already runs (`--verify-update`), and never an older build. Its ssh key
  reaches nothing on the laptop but a gate that serves the staged files.
- `bash scripts/test_harmony.sh harden` checks all of it on the devices: a stranger with a fresh
  identity is refused by both nodes, the gate refuses shells, other files and sftp, and tampered
  copies of the build fail verification.

## Use it from any OpenAI client
Each node speaks OpenAI's chat-completions API on loopback, so chat apps, editor plugins and the
official SDKs use the mesh unchanged: base URL `http://127.0.0.1:3005/v1`, any API key, model `harmony`.
```
curl -s http://127.0.0.1:3005/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"harmony","messages":[{"role":"user","content":"Hello"}]}'
```
```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:3005/v1", api_key="local")
reply = client.chat.completions.create(model="harmony", messages=[{"role": "user", "content": "Hello"}])
print(reply.choices[0].message.content)
```
- A conversation is placed like an `/infer` job: the AI placement decision in force unless the rules
  veto it, else this device; when this device is too hot or busy, the coolest idle peers are asked one
  at a time. The response's `harmony` field and its `x-harmony-device` header name the device that answered.
- Conversations are cut to 8 KB, oldest turns first. `stream: true` returns OpenAI's server-sent
  events, in one piece once the answer is complete. `"harmony": {"offload": false}` keeps a request
  on this device. `GET /v1/models` lists the mesh as one model.
- Like the rest of the operator API it answers loopback only (off loopback, `HARMONY_ADMIN_TOKEN` is
  the API key) and grants no CORS, so a web page cannot call it.

## The model stays loaded
Each node runs llama.cpp's `llama-server` once (loopback, a free port, a random API key, one slot)
and keeps the model loaded between jobs, so a job no longer pays for loading it off flash. After
`--llama-idle-secs` (15 minutes) without a job it unloads the model and the next job loads it again.
The thermal limit, cooldown and one-job-at-a-time rule sit in front of it unchanged. A node without
`llama-server` runs each job with `--llama-bin` as before (`--llama-server off` forces that).

## Run
```
cargo build --release
./target/release/rust_p2p_node --peer <other-node-ip>:3005 --llama-bin <path-to-llama-completion> \
    --cmd-allow <id of the node allowed to issue directives> \
    --trust-mode strict --trust <ids of the other nodes> --advisor <id of the node whose Llama decides>
```
`--print-id` shows a node's id. Needs Rust 1.82 or newer.

If port 3005 is taken, the node moves to the next free port (up to 3015). Peers learn the new port
from its signed handshake, and a node whose seed has moved finds it by sweeping the nearby ports,
with every hit verified by a full handshake. A second copy of the same node identity is refused
instead of joining the mesh as a clone. `bash scripts/test_harmony.sh rotate` shows all of it.

## Start and stop
`bash scripts/node.sh start|stop|restart|status` on each device (settings in `~/.harmony/node.env`).
Startup reports `starting` then `ready` in `/health`, and refuses a second copy of the same node,
naming the pid that holds it. On SIGTERM or Ctrl+C the node stops taking new jobs, reports itself
busy, says goodbye to every peer (they drop it immediately instead of after failed gossip rounds),
lets in-flight requests finish within `--shutdown-grace`, then exits; a second signal exits at once.
`bash scripts/test_harmony.sh lifecycle` checks all of it with throwaway nodes.
`POST /shutdown` (loopback, JSON) does the same as SIGTERM, for where a background process cannot
be sent a signal.

## Windows nodes
The node also runs natively on Windows. `bash scripts/win_node.sh` (on the phone) has the Linux
laptop cross-compile `rust_p2p_node.exe` with MinGW-w64, so nothing heavy is installed on the PC,
and stages it with a model and the scripts. One line in PowerShell on the PC copies them over and
runs `setup_windows.ps1`, which downloads llama.cpp's Windows CPU build, adds a firewall rule
(inbound TCP 3005-3015, this program, local network only) and starts the node in the background.
`node.cmd start|stop|restart|status|log` manages it there; stop goes through `POST /shutdown`.
`bash scripts/mesh_upgrade.sh` builds the phone, the laptop and the PC's `.exe` in one run. With
`node.cmd autosync user@laptop` (once), a hidden watcher on the PC installs each new build within
a minute and reports back, so the script ends with all three devices on the same build. It installs
only builds the phone signed, newer than the installed one, and its key opens only the laptop's
sync gate (`~/.harmony/sync_gate.sh`), never a shell.
On Windows the temperature comes from the ACPI thermal zones ("Thermal Zone Information"
performance counters, no admin rights), sampled by one hidden PowerShell process that exits with
the node.

## Demo
```
# on the phone: open http://127.0.0.1:3005/ui, then
PEER_SSH=user@laptop bash scripts/test_harmony.sh intent  # "spare the phone's battery, use the laptop": Llama's reading
                                                          # moves jobs to the laptop although the rules would keep them;
                                                          # then the laptop goes over its limit and the rules veto it
PEER_SSH=user@laptop bash scripts/test_harmony.sh reading # 13 notes through the laptop's Llama (dry runs)
PEER_SSH=user@laptop bash scripts/test_harmony.sh relay   # directive → Llama → decision back → job follows it
bash scripts/test_harmony.sh thermal                      # cool: answered locally
# restart a node with HARMONY_MOCK_TEMP=80 (or --max-temp below its temperature), then:
bash scripts/test_harmony.sh thermal                      # hot: refused locally, offloaded to the coolest peer
HEAT=1 MAX_TEMP=45 bash scripts/test_harmony.sh thermal   # real load: heat, offload, cool down, recover
PEER_SSH=user@peer bash scripts/test_harmony.sh relay     # vitals on gossip; signed directive relayed, acked, advised
```

## Use of Meta products
- **Llama 3.2 1B and 3B Instruct** (GGUF): each node carries the size its hardware allows; both demo devices
  run `standard-3b`, and `light-1b` suits devices with less memory.
- **Llama 3.1 8B Instruct** (Q4_K_M) is the default for heavy-tier hardware (`HARMONY_MODEL_HEAVY`).
- Llama produces the routing advisories and answers the inference requests that the mesh offloads between devices.
EOF
# v19: a README written by an earlier run gets the OpenAI and kept-loaded sections too, before "## Run"
if ! grep -q '^## Use it from any OpenAI client' README.md && grep -q '^## Run$' README.md; then
  OA_MD=$(cat <<'EOF'
## Use it from any OpenAI client
Each node speaks OpenAI's chat-completions API on loopback, so chat apps, editor plugins and the
official SDKs use the mesh unchanged: base URL `http://127.0.0.1:3005/v1`, any API key, model `harmony`.
```
curl -s http://127.0.0.1:3005/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"harmony","messages":[{"role":"user","content":"Hello"}]}'
```
```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:3005/v1", api_key="local")
reply = client.chat.completions.create(model="harmony", messages=[{"role": "user", "content": "Hello"}])
print(reply.choices[0].message.content)
```
- A conversation is placed like an `/infer` job: the AI placement decision in force unless the rules
  veto it, else this device; when this device is too hot or busy, the coolest idle peers are asked one
  at a time. The response's `harmony` field and its `x-harmony-device` header name the device that answered.
- Conversations are cut to 8 KB, oldest turns first. `stream: true` returns OpenAI's server-sent
  events, in one piece once the answer is complete. `"harmony": {"offload": false}` keeps a request
  on this device. `GET /v1/models` lists the mesh as one model.
- Like the rest of the operator API it answers loopback only (off loopback, `HARMONY_ADMIN_TOKEN` is
  the API key) and grants no CORS, so a web page cannot call it.

## The model stays loaded
Each node runs llama.cpp's `llama-server` once (loopback, a free port, a random API key, one slot)
and keeps the model loaded between jobs, so a job no longer pays for loading it off flash. After
`--llama-idle-secs` (15 minutes) without a job it unloads the model and the next job loads it again.
The thermal limit, cooldown and one-job-at-a-time rule sit in front of it unchanged. A node without
`llama-server` runs each job with `--llama-bin` as before (`--llama-server off` forces that).
EOF
)
  OA_MD="$OA_MD" awk '/^## Run$/ && !done { print ENVIRON["OA_MD"]; print ""; done = 1 } { print }' README.md > README.md.new \
    && mv README.md.new README.md && ok "README.md: added the OpenAI API and kept-loaded model sections (review them)"
fi

# ------------------------------------------------------------------ secret scan (hard stops)
step "secret scan"
hits=$(grep -rIlE --exclude-dir=.git -- '-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----' . || true)
[ -z "$hits" ] || die "private key material in: $hits"
for s in "$CEW/.enroll_token" "$HOME/.harmony_test/.enroll_token"; do
  [ -s "$s" ] || continue
  t=$(tr -d ' \n' < "$s"); [ ${#t} -ge 16 ] || continue
  hits=$(grep -rIlF --exclude-dir=.git -- "$t" . || true)
  [ -z "$hits" ] || die "your enrollment token is inside: $hits"
done
for k in "$CEW"/*.key "$GW"/*.key "$HOME"/.harmony_ca/*.key; do
  [ -s "$k" ] || continue
  frag=$(sed -n '2p' "$k" | cut -c1-40); [ ${#frag} -ge 24 ] || continue
  hits=$(grep -rIlF --exclude-dir=.git -- "$frag" . || true)
  [ -z "$hits" ] || die "contents of $(basename "$k") found in: $hits"
done
big=$(find . -path ./.git -prune -o -type f -size +50M -print)
[ -z "$big" ] || die "files over 50 MB (GitHub rejects >100 MB): $big"
sus=$(grep -rInEi --exclude-dir=.git '(token|secret|passw(or)?d|api[_-]?key)[A-Za-z_]*["'"'"' ]*[:=][^"'"'"'\n]{0,24}["'"'"'][A-Za-z0-9+/_=-]{16,}' . || true)
[ -z "$sus" ] && ok "no keys, tokens or large files" || { warn "literal secrets? review these lines:"; printf '%s\n' "$sus" | cut -c1-150; }

# ------------------------------------------------------------------ review
step "files to publish"
git add -A
if git diff --cached --quiet; then ok "nothing changed since the last publish"; CHANGED=0
else
  CHANGED=1
  git diff --cached --name-status | sed 's/^/  /'
  echo "  total: $(git ls-files | wc -l) files, $(du -sh --exclude=.git . 2>/dev/null | cut -f1)"
fi
if grep -q 'FILL:' README.md; then
  warn "README.md still has a FILL: section: edit ~/$NAME/README.md, then rerun"
  [ "${DRY_RUN:-0}" = 1 ] || { git reset -q; die "not publishing an unfinished README"; }
fi
if [ "${DRY_RUN:-0}" = 1 ]; then git reset -q; ok "dry run: nothing committed or published (staged copy kept in ~/$NAME)"; exit 0; fi

# ------------------------------------------------------------------ commit + push
if [ "$CHANGED" = 1 ]; then
  if [ "${YES:-0}" != 1 ]; then
    read -r -p "Publish these files PUBLICLY as github.com/$LOGIN/$NAME? [y/N] " a </dev/tty
    [[ $a == [yY]* ]] || { git reset -q; die "cancelled: nothing published"; }
  fi
  git config user.name "$LOGIN"
  git config user.email "$GHID+$LOGIN@users.noreply.github.com"   # keeps your real email out of public history
  git commit -q -m "$( [ "$(git rev-list --count HEAD 2>/dev/null || echo 0)" = 0 ] && echo "Harmony: Llama-advised thermal offloading and piggyback propagation" || echo "Update source")"
  ok "committed $(git rev-parse --short HEAD)"
fi

step "push"
if gh repo view "$LOGIN/$NAME" >/dev/null 2>&1; then
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$LOGIN/$NAME.git"
  git push -q -u origin main
else
  gh repo create "$NAME" --public --source . --remote origin --push --description "$DESC"
fi
VIS=$(gh repo view "$LOGIN/$NAME" --json visibility -q .visibility)
URL=$(gh repo view "$LOGIN/$NAME" --json url -q .url)
[ "$VIS" = PUBLIC ] || warn "repo is $VIS: the hackathon needs PUBLIC (gh repo edit $LOGIN/$NAME --visibility public --accept-visibility-change-consequences)"
ok "published: $URL"
echo "Paste that URL into the submission form."
