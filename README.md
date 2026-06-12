# Constitutional Agent Certificates (CAC)

**Agents carry governance certificates – just like websites carry TLS certificates.**

This repository demonstrates a proof‑of‑concept implementation of CAC, a system where AI agents prove their **identity, constitutional integrity, and continuity** before interacting with other agents.

## Three Layers

1. **Identity certificate** – signed by a trusted authority.
2. **Constitution hash** – points to an immutable set of governance rules.
3. **Continuity proof** – signed snapshot proving the agent is still admissible.

## Why it matters

- Existing systems verify **machine identity** (SPIFFE, X.509, OAuth).  
- CAC adds **governance continuity** and **admissibility signals** to agent trust.

A second agent can decide:  
*“I only cooperate with agents whose governance score > 80 and whose continuity proof is fresh.”*

## Run the demo

```bash
git clone ...
cd cac_demo
python demo.py