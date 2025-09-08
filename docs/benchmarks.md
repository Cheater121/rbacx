
# Benchmarks helper

Run the included micro-benchmark to compare PDP latency for different policy sizes:

```bash
python bench/bench_pdp.py --sizes 10 100 500 1000 --iters 500
```

It prints CSV to stdout (`size,avg_ms,p50_ms,p90_ms,allowed`). Use it only for relative comparisons in your environment.
