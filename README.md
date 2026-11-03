# Harmony: Llama-advised thermal offloading and piggyback propagation

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

## AI control: Llama-advised, deterministic guardrails
- A routing directive is run through the receiving node's local Llama as a *non-actuating advisory*.
  The prompt lists every device with its piggybacked temperature, thermal headroom, busy state and
  model, and asks for one line: `RECOMMEND <device> - <reason>`.
- The node compares that recommendation with the deterministic thermal ranking (coolest idle device
  below its limit) and records the verdict, e.g. `llama recommends B; thermal rules agree`.
- Placement and offload are decided only by the fixed, auditable rules. The model proposes; the rules decide.
- Advisory runs are refused at or above `--max-temp`, so a hot device doesn't spend heat on advice;
  it relays the directive anyway and advises once it cools.

## Run
```
cargo build --release
./target/release/rust_p2p_node --peer <other-node-ip>:3005 --llama-bin <path-to-llama-completion> \
    --cmd-allow <id of the node allowed to issue directives>
```
`--print-id` shows a node's id.

## Demo
```
bash scripts/test_harmony.sh thermal                      # cool: answered locally
# restart a node with HARMONY_MOCK_TEMP=80 (or --max-temp below its temperature), then:
bash scripts/test_harmony.sh thermal                      # hot: refused locally, offloaded to the coolest peer
HEAT=1 MAX_TEMP=45 bash scripts/test_harmony.sh thermal   # real load: heat, offload, cool down, recover
PEER_SSH=user@peer bash scripts/test_harmony.sh relay     # vitals on gossip; signed directive relayed, acked, advised
```

## Use of Meta products
- **Llama 3.2 1B and 3B Instruct** (GGUF) on the demo devices: each node carries the size its hardware allows
  (`light-1b` on the laptop, `standard-3b` on the phone).
- **Llama 3.1 8B Instruct** (Q4_K_M) is the default for heavy-tier hardware (`HARMONY_MODEL_HEAVY`).
- Llama produces the routing advisories and answers the inference requests that the mesh offloads between devices.
