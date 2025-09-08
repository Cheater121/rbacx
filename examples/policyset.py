from rbacx.core.policyset import decide as decide_policyset

def main() -> None:
    p1 = {"rules":[{"id":"r1","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]}
    p2 = {"rules":[{"id":"r2","effect":"deny","actions":["delete"],"resource":{"type":"doc"}}]}
    ps = {"algorithm":"deny-overrides","policies":[p1, p2]}
    env = {"subject":{"id":"u"}, "action":"read", "resource":{"type":"doc","id":"1","attrs":{}}}
    res = decide_policyset(ps, env)
    print(res["decision"], res["reason"])  # permit, matched

if __name__ == "__main__":
    main()
