//! Benchmarks for Citadel Mesh Topology
//!
//! Measures performance of:
//! - SPIRAL 3D index computation
//! - Coordinate conversions
//! - Neighbor lookups
//! - Routing simulation

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use citadel_topology::{
    HexCoord, Neighbors, Spiral3D, Spiral3DIndex,
    spiral3d_to_coord, coord_to_spiral3d,
    slots_in_shell, total_slots_through_shell,
};

/// Benchmark spiral index to coordinate conversion
fn bench_spiral_to_coord(c: &mut Criterion) {
    let mut group = c.benchmark_group("spiral_to_coord");

    // Test at different scales
    for &index in &[0u64, 10, 100, 1000, 10_000, 100_000, 1_000_000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(index),
            &index,
            |b, &idx| {
                b.iter(|| spiral3d_to_coord(black_box(Spiral3DIndex(idx))))
            },
        );
    }
    group.finish();
}

/// Benchmark coordinate to spiral index conversion
fn bench_coord_to_spiral(c: &mut Criterion) {
    let mut group = c.benchmark_group("coord_to_spiral");

    // Generate coordinates at different distances from origin
    let coords = [
        HexCoord::ORIGIN,
        HexCoord::new(1, 0, 0),
        HexCoord::new(5, -3, 2),
        HexCoord::new(10, -5, 8),
        HexCoord::new(50, -25, 30),
        HexCoord::new(100, -50, 75),
    ];

    for coord in coords {
        let shell = coord.z.unsigned_abs()
            .max(coord.hex_distance(&HexCoord::new(0, 0, coord.z)));
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("shell", shell),
            &coord,
            |b, &c| {
                b.iter(|| coord_to_spiral3d(black_box(c)))
            },
        );
    }
    group.finish();
}

/// Benchmark shell detection
fn bench_shell_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("shell_detection");

    for &index in &[0u64, 20, 94, 258, 10_000, 100_000, 1_000_000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(index),
            &index,
            |b, &idx| {
                let spiral_idx = Spiral3DIndex(idx);
                b.iter(|| black_box(spiral_idx).shell())
            },
        );
    }
    group.finish();
}

/// Benchmark neighbor computation
fn bench_neighbors(c: &mut Criterion) {
    let mut group = c.benchmark_group("neighbors");

    let coords = [
        HexCoord::ORIGIN,
        HexCoord::new(5, -3, 2),
        HexCoord::new(50, -25, 30),
    ];

    for coord in coords {
        let shell = coord.z.unsigned_abs()
            .max(coord.hex_distance(&HexCoord::new(0, 0, coord.z)));
        group.throughput(Throughput::Elements(20)); // 20 neighbors
        group.bench_with_input(
            BenchmarkId::new("shell", shell),
            &coord,
            |b, &c| {
                b.iter(|| Neighbors::of(black_box(c)))
            },
        );
    }
    group.finish();
}

/// Benchmark batch iteration over spiral
fn bench_spiral_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("spiral_iteration");

    for &count in &[100u64, 1000, 10_000, 100_000] {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, &n| {
                b.iter(|| {
                    Spiral3D::take_slots(black_box(n)).count()
                })
            },
        );
    }
    group.finish();
}

/// Benchmark shell size formulas
fn bench_shell_formulas(c: &mut Criterion) {
    let mut group = c.benchmark_group("shell_formulas");

    for &shell in &[1u64, 10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("slots_in_shell", shell),
            &shell,
            |b, &n| {
                b.iter(|| slots_in_shell(black_box(n)))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("total_through_shell", shell),
            &shell,
            |b, &n| {
                b.iter(|| total_slots_through_shell(black_box(n)))
            },
        );
    }
    group.finish();
}

/// Benchmark round-trip conversion
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for &index in &[0u64, 100, 1000, 10_000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(index),
            &index,
            |b, &idx| {
                b.iter(|| {
                    let coord = spiral3d_to_coord(Spiral3DIndex(black_box(idx)));
                    coord_to_spiral3d(coord)
                })
            },
        );
    }
    group.finish();
}

/// Simulate greedy routing and measure hop count
fn bench_routing_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("routing_simulation");

    // Pre-compute some source/destination pairs
    let pairs: Vec<(HexCoord, HexCoord)> = vec![
        (HexCoord::ORIGIN, spiral3d_to_coord(Spiral3DIndex(100))),
        (spiral3d_to_coord(Spiral3DIndex(50)), spiral3d_to_coord(Spiral3DIndex(200))),
        (spiral3d_to_coord(Spiral3DIndex(1000)), spiral3d_to_coord(Spiral3DIndex(5000))),
    ];

    for (idx, (src, dst)) in pairs.iter().enumerate() {
        let distance = hex_distance_3d(src, dst);
        group.bench_with_input(
            BenchmarkId::new("pair", format!("{}_dist{}", idx, distance)),
            &(*src, *dst),
            |b, &(s, d)| {
                b.iter(|| greedy_route(black_box(s), black_box(d)))
            },
        );
    }
    group.finish();
}

/// 3D hex distance (max of planar distance and z difference)
fn hex_distance_3d(a: &HexCoord, b: &HexCoord) -> u64 {
    let planar_a = HexCoord::new(a.q, a.r, 0);
    let planar_b = HexCoord::new(b.q, b.r, 0);
    let planar_dist = planar_a.hex_distance(&planar_b);
    let z_dist = (a.z - b.z).unsigned_abs();
    planar_dist.max(z_dist)
}

/// Greedy routing: at each hop, pick the neighbor closest to destination
fn greedy_route(src: HexCoord, dst: HexCoord) -> (u64, Vec<HexCoord>) {
    let mut current = src;
    let mut path = vec![current];
    let mut hops = 0u64;

    const MAX_HOPS: u64 = 10000;

    while current != dst && hops < MAX_HOPS {
        let neighbors = Neighbors::of(current);

        // Find neighbor closest to destination
        let mut best = current;
        let mut best_dist = hex_distance_3d(&current, &dst);

        for neighbor in neighbors.iter() {
            let dist = hex_distance_3d(neighbor, &dst);
            if dist < best_dist {
                best = *neighbor;
                best_dist = dist;
            }
        }

        if best == current {
            // No progress possible (shouldn't happen in infinite mesh)
            break;
        }

        current = best;
        path.push(current);
        hops += 1;
    }

    (hops, path)
}

/// Benchmark routing at scale
fn bench_routing_at_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("routing_scale");
    group.sample_size(50); // Fewer samples for expensive operations

    // Test routing between nodes at increasing distances
    for &shell in &[5u64, 10, 20, 50] {
        // Route from origin to a node at shell boundary
        let dst = spiral3d_to_coord(Spiral3DIndex(total_slots_through_shell(shell) - 1));
        let _expected_hops = shell; // Should be roughly O(shell)

        group.bench_with_input(
            BenchmarkId::new("shell_distance", shell),
            &dst,
            |b, &d| {
                b.iter(|| greedy_route(black_box(HexCoord::ORIGIN), black_box(d)))
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_spiral_to_coord,
    bench_coord_to_spiral,
    bench_shell_detection,
    bench_neighbors,
    bench_spiral_iteration,
    bench_shell_formulas,
    bench_roundtrip,
    bench_routing_simulation,
    bench_routing_at_scale,
);

criterion_main!(benches);
