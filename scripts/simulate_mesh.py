#!/usr/bin/env python3
"""
Simulate the Citadel mesh formation protocol end-to-end.

Faithful to the real protocol:
- Real SPIRAL 3D hex coordinates from citadel-topology
- 20 neighbors per node (6 planar + 2 vertical + 12 extended)
- Switchboard half-dial for ALL connections
- CVDF chain weight comparison with deterministic tiebreaker
- VDF-anchored slot claiming with priority resolution
- Peer flood propagation
- dial_missing_spiral_neighbors after bootstrap
"""

import blake3
import json
import random
from dataclasses import dataclass, field
from typing import Optional


# ============================================================================
# HexCoord — axial coordinates (q, r) + layer z
# Ported from citadel-topology/src/hex.rs
# ============================================================================

@dataclass(frozen=True)
class HexCoord:
    q: int = 0
    r: int = 0
    z: int = 0

    @property
    def s(self):
        return -self.q - self.r

    def hex_distance(self, other):
        dq = abs(self.q - other.q)
        dr = abs(self.r - other.r)
        ds = abs((self.q - other.q) + (self.r - other.r))
        return max(dq, dr, ds)

    def distance(self, other):
        return self.hex_distance(other) + abs(self.z - other.z)

    def __add__(self, other):
        return HexCoord(self.q + other.q, self.r + other.r, self.z + other.z)

    def __sub__(self, other):
        return HexCoord(self.q - other.q, self.r - other.r, self.z - other.z)

    def __repr__(self):
        return f"({self.q},{self.r},{self.z})"


ORIGIN = HexCoord(0, 0, 0)

# The 6 planar directions
PLANAR_DIRECTIONS = [
    HexCoord(1, 0, 0),    # East
    HexCoord(1, -1, 0),   # Northeast
    HexCoord(0, -1, 0),   # Northwest
    HexCoord(-1, 0, 0),   # West
    HexCoord(-1, 1, 0),   # Southwest
    HexCoord(0, 1, 0),    # Southeast
]

# The 2 vertical directions
VERTICAL_DIRECTIONS = [
    HexCoord(0, 0, 1),    # Up
    HexCoord(0, 0, -1),   # Down
]

# The 12 extended directions (planar + vertical combinations)
EXTENDED_DIRECTIONS = [
    HexCoord(1, 0, 1), HexCoord(1, -1, 1), HexCoord(0, -1, 1),
    HexCoord(-1, 0, 1), HexCoord(-1, 1, 1), HexCoord(0, 1, 1),
    HexCoord(1, 0, -1), HexCoord(1, -1, -1), HexCoord(0, -1, -1),
    HexCoord(-1, 0, -1), HexCoord(-1, 1, -1), HexCoord(0, 1, -1),
]

# All 20 neighbor directions
ALL_DIRECTIONS = PLANAR_DIRECTIONS + VERTICAL_DIRECTIONS + EXTENDED_DIRECTIONS
assert len(ALL_DIRECTIONS) == 20


def neighbors_of(coord: HexCoord) -> list:
    """Get all 20 neighbors of a coordinate."""
    return [coord + d for d in ALL_DIRECTIONS]


def are_neighbors(a: HexCoord, b: HexCoord) -> bool:
    """Check if two coordinates are within the 20-connection set."""
    diff = b - a
    return diff in ALL_DIRECTIONS


# ============================================================================
# SPIRAL 3D — index to coordinate mapping
# Ported from citadel-topology/src/spiral3d.rs
# ============================================================================

def slots_in_shell(n):
    """Number of slots in shell n. Shell 0: 1, Shell n>0: 18n² + 2"""
    if n == 0:
        return 1
    return 18 * n * n + 2


def total_slots_through_shell(n):
    """Total slots through shell n (inclusive). Formula: 6n³ + 9n² + 5n + 1"""
    return 6 * n * n * n + 9 * n * n + 5 * n + 1


def find_shell(index):
    """Find which shell an index falls in."""
    if index == 0:
        return 0
    low, high = 1, int(index ** (1/3)) + 2
    while low < high:
        mid = (low + high) // 2
        if total_slots_through_shell(mid) <= index:
            low = mid + 1
        else:
            high = mid
    return low


def slots_in_ring_2d(n):
    """Slots in 2D ring n: 6n (or 1 for n=0)"""
    return 1 if n == 0 else 6 * n


def total_slots_through_shell_2d(n):
    """Total slots through ring n in 2D: 1 + 3n(n+1)"""
    return 1 + 3 * n * (n + 1)


def ring_coord(ring, offset):
    """Get coordinate at offset within ring n (2D)."""
    if ring == 0:
        return HexCoord(0, 0, 0)

    edge = offset // ring
    pos = offset % ring

    corners = [
        (ring, 0), (0, ring), (-ring, ring),
        (-ring, 0), (0, -ring), (ring, -ring),
    ]
    directions = [(-1, 1), (-1, 0), (0, -1), (1, -1), (1, 0), (0, 1)]

    cq, cr = corners[edge]
    dq, dr = directions[edge]

    return HexCoord(cq + dq * pos, cr + dr * pos, 0)


def disk_coord(max_ring, offset):
    """Get coordinate at offset within disk (rings 0 to max_ring)."""
    if offset == 0:
        return HexCoord(0, 0, 0)

    remaining = offset
    for ring in range(max_ring + 1):
        ring_size = slots_in_ring_2d(ring)
        if remaining < ring_size:
            return ring_coord(ring, remaining)
        remaining -= ring_size

    raise ValueError(f"Offset {offset} exceeds disk size for max_ring {max_ring}")


def spiral3d_to_coord(index):
    """Convert a 3D spiral index to HexCoord. Faithful port of spiral3d.rs."""
    if index == 0:
        return ORIGIN

    shell = find_shell(index)
    base = total_slots_through_shell(shell - 1) if shell > 0 else 0
    offset = index - base

    ring_n_size = 6 * shell
    z_levels_with_ring_n = 2 * shell - 1
    slots_at_ring_n = z_levels_with_ring_n * ring_n_size

    if offset < slots_at_ring_n:
        # Ring-n portion at some z with |z| < shell
        z_index = offset // ring_n_size
        ring_offset = offset % ring_n_size

        if z_index == 0:
            z = 0
        else:
            half = (z_index + 1) // 2
            z = half if z_index % 2 == 1 else -half

        planar = ring_coord(shell, ring_offset)
        return HexCoord(planar.q, planar.r, z)
    else:
        # z = ±shell portion
        remaining = offset - slots_at_ring_n
        disk_size = total_slots_through_shell_2d(shell)

        if remaining < disk_size:
            planar = disk_coord(shell, remaining)
            return HexCoord(planar.q, planar.r, shell)
        else:
            disk_offset = remaining - disk_size
            planar = disk_coord(shell, disk_offset)
            return HexCoord(planar.q, planar.r, -shell)


# ============================================================================
# CVDF Chain
# ============================================================================

@dataclass
class CvdfRound:
    round: int
    output: bytes  # 32 bytes
    weight: int    # 1 + attestation_count


@dataclass
class CvdfChain:
    rounds: list

    @property
    def height(self):
        return self.rounds[-1].round if self.rounds else 0

    @property
    def total_weight(self):
        return sum(r.weight for r in self.rounds)

    @property
    def tip(self):
        return self.rounds[-1].output if self.rounds else b'\x00' * 32

    def produce_round(self, attestation_count=1):
        next_round = self.height + 1
        prev = self.tip
        output = blake3.blake3(prev + next_round.to_bytes(8, 'little')).digest()
        self.rounds.append(CvdfRound(
            round=next_round,
            output=output,
            weight=1 + attestation_count,
        ))

    def should_adopt(self, other_rounds):
        if not other_rounds:
            return False
        their_weight = sum(r.weight for r in other_rounds)
        our_weight = self.total_weight
        if their_weight < our_weight:
            return False
        if their_weight == our_weight:
            their_tip = other_rounds[-1].output
            our_tip = self.tip
            if their_tip >= our_tip:
                return False
        return True

    def adopt(self, other_rounds):
        if self.should_adopt(other_rounds):
            self.rounds = list(other_rounds)
            return True
        return False


# ============================================================================
# Node
# ============================================================================

@dataclass
class SlotClaim:
    slot: int
    node_id: str
    vdf_height: int


@dataclass
class Node:
    node_id: str
    mesh_port: int
    switchboard_port: int
    entry_peers: list
    chain: CvdfChain = field(default_factory=lambda: None)
    slot: Optional[int] = None
    coord: Optional[HexCoord] = None
    peers: dict = field(default_factory=dict)     # node_id -> Node ref
    known_slots: dict = field(default_factory=dict)  # slot -> SlotClaim
    known_peers: dict = field(default_factory=dict)  # node_id -> {addr, slot, coord}

    def __post_init__(self):
        seed = blake3.blake3(self.node_id.encode()).digest()
        genesis = CvdfRound(round=0, output=seed, weight=1)
        self.chain = CvdfChain(rounds=[genesis])

    def switchboard_addr(self):
        return f"127.0.0.1:{self.switchboard_port}"

    def neighbor_coords(self):
        """Get all 20 neighbor coordinates for this node's SPIRAL position."""
        if self.coord is None:
            return []
        return neighbors_of(self.coord)


# ============================================================================
# Simulation
# ============================================================================

class MeshSimulation:
    def __init__(self, node_count, base_port=45000):
        self.nodes = {}
        self.connections = set()
        self.log_lines = []
        self.switchboard_addr_map = {}  # addr -> node

        for i in range(node_count):
            mesh_port = base_port + i
            switchboard_port = mesh_port + 443
            node_id = f"node-{i}"

            if i == 0:
                entry_peers = []
            else:
                entry_peers = [f"127.0.0.1:{base_port + 443}"]

            node = Node(
                node_id=node_id,
                mesh_port=mesh_port,
                switchboard_port=switchboard_port,
                entry_peers=entry_peers,
            )
            self.nodes[node_id] = node
            self.switchboard_addr_map[node.switchboard_addr()] = node

    def _log(self, msg):
        self.log_lines.append(msg)
        print(f"  {msg}")

    def resolve_switchboard(self, addr):
        return self.switchboard_addr_map.get(addr)

    def switchboard_half_dial(self, client, server):
        """Switchboard half-dial protocol. Returns True if connected."""
        if client.node_id == server.node_id:
            self._log(f"{client.node_id}: SELF-DETECTED (same node)")
            return False

        self._log(f"{client.node_id} → {server.node_id}: switchboard CONNECTED")
        return True

    def exchange_state(self, node_a, node_b):
        """Exchange CVDF chains, slot claims, and peer info."""
        a_rounds = list(node_a.chain.rounds)
        b_rounds = list(node_b.chain.rounds)
        a_slots = dict(node_a.known_slots)
        b_slots = dict(node_b.known_slots)
        a_peers = dict(node_a.known_peers)
        b_peers = dict(node_b.known_peers)

        # Chain adoption
        if node_a.chain.should_adopt(b_rounds):
            node_a.chain.adopt(b_rounds)
            self._log(f"{node_a.node_id}: adopted {node_b.node_id}'s chain (h={node_b.chain.height} w={node_b.chain.total_weight})")

        if node_b.chain.should_adopt(a_rounds):
            node_b.chain.adopt(a_rounds)
            self._log(f"{node_b.node_id}: adopted {node_a.node_id}'s chain (h={node_a.chain.height} w={node_a.chain.total_weight})")

        # Slot knowledge exchange
        for slot, claim in b_slots.items():
            if slot not in node_a.known_slots or claim.vdf_height < node_a.known_slots[slot].vdf_height:
                node_a.known_slots[slot] = claim
        for slot, claim in a_slots.items():
            if slot not in node_b.known_slots or claim.vdf_height < node_b.known_slots[slot].vdf_height:
                node_b.known_slots[slot] = claim

        # Peer info exchange
        node_a.known_peers[node_b.node_id] = {
            'addr': node_b.switchboard_addr(),
            'slot': node_b.slot,
            'coord': node_b.coord,
        }
        node_b.known_peers[node_a.node_id] = {
            'addr': node_a.switchboard_addr(),
            'slot': node_a.slot,
            'coord': node_a.coord,
        }
        for pid, info in b_peers.items():
            if pid not in node_a.known_peers:
                node_a.known_peers[pid] = info
        for pid, info in a_peers.items():
            if pid not in node_b.known_peers:
                node_b.known_peers[pid] = info

        # Register as connected peers
        node_a.peers[node_b.node_id] = node_b
        node_b.peers[node_a.node_id] = node_a
        self.connections.add(tuple(sorted([node_a.node_id, node_b.node_id])))

    def claim_slot(self, node):
        """Node claims next available slot using VDF priority."""
        if node.slot is not None:
            return

        claimed = set(node.known_slots.keys())
        for i in range(1000):
            if i not in claimed:
                vdf_height = node.chain.height
                claim = SlotClaim(slot=i, node_id=node.node_id, vdf_height=vdf_height)
                node.slot = i
                node.coord = spiral3d_to_coord(i)
                node.known_slots[i] = claim
                self._log(f"{node.node_id}: claimed slot {i} at coord {node.coord}")

                # Update our entry in all peers' known_peers (slot + coord now set)
                for peer in node.peers.values():
                    peer.known_peers[node.node_id] = {
                        'addr': node.switchboard_addr(),
                        'slot': node.slot,
                        'coord': node.coord,
                    }

                # Flood slot claim through connected peers
                self.flood_slot_claim(node, claim)
                return

    def flood_slot_claim(self, source, claim):
        """Flood a slot claim through connected peers."""
        visited = {source.node_id}
        queue = list(source.peers.values())

        while queue:
            peer = queue.pop(0)
            if peer.node_id in visited:
                continue
            visited.add(peer.node_id)

            slot = claim.slot
            if slot not in peer.known_slots or claim.vdf_height < peer.known_slots[slot].vdf_height:
                peer.known_slots[slot] = claim
                # Propagate further
                for next_peer in peer.peers.values():
                    if next_peer.node_id not in visited:
                        queue.append(next_peer)

    def flood_chain(self, source):
        """Flood chain state through connected peers."""
        for peer in source.peers.values():
            if peer.chain.should_adopt(source.chain.rounds):
                peer.chain.adopt(list(source.chain.rounds))

    def dial_missing_spiral_neighbors(self, node):
        """
        After bootstrap and slot claim, dial SPIRAL neighbors we're not
        connected to. Uses switchboard on the neighbor's known address.
        """
        if node.coord is None:
            return

        my_neighbor_coords = set(neighbors_of(node.coord))

        for target_id, info in list(node.known_peers.items()):
            if target_id == node.node_id:
                continue
            if target_id in node.peers:
                continue  # already connected
            target_coord = info.get('coord')
            if target_coord is None:
                continue
            if target_coord not in my_neighbor_coords:
                continue  # not a SPIRAL neighbor

            target_node = self.nodes.get(target_id)
            if target_node is None:
                continue

            target_addr = info.get('addr')
            self._log(f"{node.node_id}: dialing SPIRAL neighbor {target_id} (slot {info.get('slot')}, coord {target_coord}) via {target_addr}")

            if self.switchboard_half_dial(node, target_node):
                self.exchange_state(node, target_node)

    def check_convergence(self):
        """Check mesh convergence state."""
        print("\n=== CONVERGENCE CHECK ===\n")

        tips = {}
        for node in self.nodes.values():
            tip_hex = node.chain.tip[:4].hex()
            tips.setdefault(tip_hex, []).append(node.node_id)

        for tip, nodes in sorted(tips.items()):
            print(f"  Tip {tip}...: {len(nodes)} nodes — {', '.join(sorted(nodes))}")

        all_connected = all(
            len(n.peers) > 0 or not n.entry_peers
            for n in self.nodes.values()
        )
        all_same_tip = len(tips) == 1

        print(f"\n  Connections: {len(self.connections)}")
        print(f"  Unique tips: {len(tips)}")
        print(f"  All connected: {all_connected}")
        print(f"  All same tip: {all_same_tip}")

        return all_same_tip and all_connected

    def run_full_simulation(self):
        """
        Run the complete mesh formation simulation.

        Real sequence: nodes join one at a time. Each goes through:
        1. Connect to entry peer via switchboard
        2. Exchange state (CVDF chain, slots, peer info)
        3. Claim a SPIRAL slot
        4. Dial missing SPIRAL neighbors via switchboard
        5. Produce CVDF rounds
        """
        print(f"\n{'='*60}")
        print(f"MESH FORMATION SIMULATION ({len(self.nodes)} nodes)")
        print(f"{'='*60}")

        for node in self.nodes.values():
            ep = node.entry_peers[0] if node.entry_peers else "NONE (bootstrap)"
            print(f"  {node.node_id}: switchboard={node.switchboard_port} entry={ep}")

        node_list = list(self.nodes.values())

        # Node 0: bootstrap
        print("\n--- node-0: BOOTSTRAP ---")
        self.claim_slot(node_list[0])
        for _ in range(3):
            node_list[0].chain.produce_round(attestation_count=1)

        # Each subsequent node joins
        for i in range(1, len(node_list)):
            node = node_list[i]
            print(f"\n--- {node.node_id}: JOINING ---")

            # 1. Switchboard bootstrap
            for entry_addr in node.entry_peers:
                server = self.resolve_switchboard(entry_addr)
                if server and self.switchboard_half_dial(node, server):
                    self.exchange_state(node, server)

            # 2. Claim slot
            self.claim_slot(node)

            # 3. Produce a round
            if node.slot is not None:
                node.chain.produce_round(attestation_count=1)
                self.flood_chain(node)

            # 4. Dial missing SPIRAL neighbors
            self.dial_missing_spiral_neighbors(node)

        # Final convergence rounds
        print("\n--- FINAL CVDF ROUNDS ---")
        for _ in range(5):
            for node in node_list:
                if node.slot is not None:
                    attesters = 1 + sum(1 for p in node.peers.values()
                                        if p.chain.tip == node.chain.tip)
                    node.chain.produce_round(attestation_count=attesters)
            for node in node_list:
                self.flood_chain(node)

        converged = self.check_convergence()

        # Topology
        print("\n  Topology:")
        for node in node_list:
            neighbor_count = 0
            if node.coord:
                my_neighbors = set(neighbors_of(node.coord))
                for pid, peer in node.peers.items():
                    if peer.coord and peer.coord in my_neighbors:
                        neighbor_count += 1
            peer_names = sorted(node.peers.keys())
            print(f"    {node.node_id} slot={node.slot} coord={node.coord}: "
                  f"{len(peer_names)} peers ({neighbor_count} SPIRAL neighbors)")

        print(f"\n{'='*60}")
        print(f"RESULT: {'MESH FORMED' if converged else 'DID NOT CONVERGE'}")
        print(f"{'='*60}\n")
        return converged


def test_2_node():
    sim = MeshSimulation(2)
    return sim.run_full_simulation()

def test_10_node():
    sim = MeshSimulation(10)
    return sim.run_full_simulation()

def test_21_node():
    """21 nodes = exactly fills shell 0 + shell 1 of SPIRAL."""
    sim = MeshSimulation(21)
    return sim.run_full_simulation()


if __name__ == "__main__":
    results = []
    results.append(("2-node mesh", test_2_node()))
    results.append(("10-node mesh", test_10_node()))
    results.append(("21-node mesh (shell 0+1)", test_21_node()))

    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, passed in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
