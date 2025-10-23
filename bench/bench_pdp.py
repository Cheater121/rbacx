import argparse
import statistics
import time

from rbacx import Action, Context, Guard, Resource, Subject


def gen_policy(n: int) -> dict:
    rules = []
    for i in range(n - 1):
        rules.append(
            {
                "id": f"permit_{i}",
                "effect": "permit",
                "actions": ["read"],
                "resource": {"type": "doc", "attrs": {"k": i}},
                "condition": {"==": [{"attr": "resource.attrs.k"}, i]},
            }
        )
    rules.append(
        {"id": "deny_other", "effect": "deny", "actions": ["read"], "resource": {"type": "doc"}}
    )
    return {"algorithm": "permit-overrides", "rules": rules}


def run(size: int, iters: int):
    pol = gen_policy(size)
    guard = Guard(pol)  # compiles under the hood
    s = Subject(id="u")
    r = Resource(type="doc", attrs={"k": size // 2})
    a = Action("read")
    c = Context()
    lat = []
    for _ in range(iters):
        t0 = time.perf_counter()
        d = guard.evaluate_sync(s, a, r, c)
        lat.append((time.perf_counter() - t0) * 1000.0)
    return {
        "p50": statistics.median(lat),
        "avg": sum(lat) / len(lat),
        "p90": percentile(lat, 90),
        "allowed": d.allowed,
    }


def percentile(arr, p):
    arr2 = sorted(arr)
    k = int(round((p / 100.0) * (len(arr2) - 1)))
    return arr2[k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[10, 50, 100, 500, 1000])
    ap.add_argument("--iters", type=int, default=200)
    args = ap.parse_args()
    print("size,avg_ms,p50_ms,p90_ms,allowed")
    for s in args.sizes:
        r = run(s, args.iters)
        print(f"{s},{r['avg']:.3f},{r['p50']:.3f},{r['p90']:.3f},{r['allowed']}")


if __name__ == "__main__":
    main()
