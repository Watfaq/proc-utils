use criterion::{criterion_group, criterion_main, Criterion};
use proc_utils::{find_process_by_socket, Network};

fn run_find_process_by_socket() {
    let _ = find_process_by_socket(None, Some(65535), Network::Tcp);
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("find_process_by_socket", |b| {
        b.iter(|| run_find_process_by_socket())
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
