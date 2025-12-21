It's not real unless it's:
* Developed using strict TEST DRIVEN DEVELOPMENT
* Proven and verifiable in Lean4
* Working in Rust with TESTS
* Visualized in browser

And finally
* Implemented as WASM in-browser

## Palace global development rules
* Always ensure pre-commit is setup and installed in this repository
* Use /commit (palace:commit) regularly to commit work whenever it's tested and finished

## FORBIDDEN PATTERNS
* **NO SLEEPS. NO POLLING. NO DELAYS.** - Sleeps, waits, and polling are ANTIPATTERNS and EXPRESSLY FORBIDDEN everywhere, including test scripts. Use async event-driven patterns ONLY.
* No "FOR NOW" compromises - Do it right or don't do it
* No "TODO" or "SIMPLIFIED IMPLEMENTATION" - Complete implementations only

## SPIRAL - Core Invariants
* **SPIRAL is DETERMINISTIC GLOBAL TOPOLOGY** - Given a slot index, anyone can compute hex coordinates. Same math = same result everywhere.
* **SLOTS CAN SWAP VIA PROOF OF LATENCY** - VDF proves time passed (can't fake waiting). Two nodes measure average latency to their 20 neighbors using VDF-backed proofs. Swap is Pareto improvement: BOTH parties must strictly benefit. Protocol: PROPOSE → HALFLOCK (maintain connections to BOTH old AND new neighbors) → bilateral ATTACK/RETREAT (TGP-style). Any RETREAT aborts. Zero sync interruption - current connections maintained throughout. See proofs/CitadelProofs/ProofOfLatency.lean.
* **DEAD SLOTS GET FILLED, NOT SHIFTED** - When a node dies, its slot becomes available. NEW NODES claim dead slots. Nobody shifts.
* **NO COORDINATION NEEDED** - Everyone independently computes the same topology because math is deterministic.
* **SWARM MERGES** - When swarms reconnect, heavier CVDF chain wins. Losing swarm's nodes get reallocated into available slots in winning topology. Reallocations go through consensus rounds which serve dual purpose: slot assignment AND TGP connection establishment happen together. The reallocation process IS the connection process.
* **NO TCP. EVER.** - All coordination is via UDP over TGP (UoTG). Connection is a cryptographic proof (QuadProof), not a socket.
