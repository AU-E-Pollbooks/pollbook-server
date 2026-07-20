#!/usr/bin/env python3
"""
Plot the contention test beds from client_misbehaviour.py.

Reads an untrusted_latencies.csv (rows: phase,latency_ms,ok,meta_json) and
renders figures for whichever test bed's phases are present:

  attacker-reaction-under-load  -> phase 'attacker_reaction'
        * attacker_reaction_hist.png  (reaction-time distribution + p50 line)
        * attacker_reaction_box.png   (reaction vs honest-load check-in, if present)

  honest-latency-under-attack   -> phases 'checkin_honest_baseline' +
                                    'checkin_honest_under_attack'
        * honest_latency_baseline_vs_attack_box.png
        * honest_latency_baseline_vs_attack_cdf.png

Each figure group is skipped if its phases are absent, so you can point this at
the CSV from either run. Usage:

  python3 plot_contention.py logs/metrics/untrusted_latencies.csv
  python3 plot_contention.py logs/metrics/untrusted_latencies.csv --outdir figs
"""
import argparse
import csv
import json
import re
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def load_phases(csv_path: Path, only_ok: bool = False):
    """Return {phase: [latency_ms, ...]} from the CSV."""
    phases = {}
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                lat = float(row["latency_ms"])
            except (KeyError, ValueError, TypeError):
                continue
            ok = str(row.get("ok", "")).strip().lower() in ("true", "1", "yes")
            if only_ok and not ok:
                continue
            phases.setdefault(row.get("phase", ""), []).append(lat)
    return phases


def load_reaction_by_attack(csv_path: Path, phase: str = "attacker_reaction",
                            only_ok: bool = False):
    """Return {attack_name: [latency_ms, ...]} for rows of `phase`, splitting on
    each row's meta.attack. Lets a 'mixed' run be disaggregated per attack."""
    out = {}
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("phase", "") != phase:
                continue
            try:
                lat = float(row["latency_ms"])
            except (KeyError, ValueError, TypeError):
                continue
            ok = str(row.get("ok", "")).strip().lower() in ("true", "1", "yes")
            if only_ok and not ok:
                continue
            attack = "unknown"
            try:
                attack = json.loads(row.get("meta_json", "") or "{}").get("attack", "unknown")
            except (ValueError, TypeError):
                pass
            out.setdefault(attack, []).append(lat)
    return dict(sorted(out.items()))


def pct(xs, p):
    ys = sorted(xs)
    if not ys:
        return float("nan")
    r = (p / 100.0) * (len(ys) - 1)
    lo = int(r)
    hi = min(lo + 1, len(ys) - 1)
    frac = r - lo
    return ys[lo] * (1 - frac) + ys[hi] * frac


def _family(phases, pattern):
    """Collect sweep phases matching `pattern` (one capture group = the integer
    level) into {level: [latencies]}, sorted by level."""
    rx = re.compile(pattern)
    out = {}
    for ph, vals in phases.items():
        m = rx.fullmatch(ph)
        if m:
            out[int(m.group(1))] = vals
    return dict(sorted(out.items()))


def stat_line(name, xs):
    if not xs:
        return f"  {name}: (no data)"
    return (f"  {name}: n={len(xs)} min={min(xs):.1f} p50={pct(xs, 50):.1f} "
            f"mean={statistics.fmean(xs):.1f} p95={pct(xs, 95):.1f} "
            f"p99={pct(xs, 99):.1f} max={max(xs):.1f} ms")


def _boxplot(series, outpath, ylabel, title, subtitle=None, ymax=None):
    labels = [n for n, _ in series]
    data = [d for _, d in series]
    plt.figure(figsize=(7, 5))
    plt.boxplot(data, whis=(5, 95), showfliers=True)
    plt.xticks(range(1, len(labels) + 1), labels)
    plt.ylabel(ylabel)
    plt.title(title)
    if ymax is not None:
        plt.ylim(bottom=0, top=ymax)  # cap so a lone flier doesn't squish the boxes
    if subtitle:
        plt.suptitle(subtitle, fontsize=9, y=0.98)
    plt.grid(True, axis="y", linestyle="--", linewidth=0.5)
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close()
    print(f"[OK] wrote {outpath}")


def _cdf(series, outpath, xlabel, title):
    plt.figure(figsize=(7, 5))
    for name, data in series:
        ys = sorted(data)
        if not ys:
            continue
        cum = [(i + 1) / len(ys) for i in range(len(ys))]
        plt.plot(ys, cum, marker=".", linestyle="-", label=name)
    plt.xlabel(xlabel)
    plt.ylabel("Cumulative fraction")
    plt.title(title)
    plt.grid(True, linestyle="--", linewidth=0.5)
    plt.legend()
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close()
    print(f"[OK] wrote {outpath}")


def plot_attacker_reaction(phases, outdir, csv_path=None, only_ok=False):
    reaction = phases.get("attacker_reaction", [])
    if not reaction:
        return False
    print("[test bed 1] attacker-reaction-under-load")
    print(stat_line("attacker_reaction", reaction))
    honest_load = phases.get("checkin_honest_load", [])
    if honest_load:
        print(stat_line("checkin_honest_load (background)", honest_load))

    # A MIXED run pools several mechanistically-different attacks, so the pooled
    # histogram is a mixture distribution (multimodal + misleading). Skip it —
    # the per-attack box plot is the canonical figure. Only draw the pooled hist
    # for a genuine single-attack run.
    n_attacks = 0
    if csv_path is not None:
        n_attacks = len({a for a, v in
                         load_reaction_by_attack(csv_path, "attacker_reaction", only_ok).items() if v})
    if n_attacks > 1:
        print("  [skip] pooled histogram omitted for a mixed run "
              "(use attacker_reaction_by_attack_box.png)")
        return True

    # single-attack: histogram with x clipped to p99 so a lone outlier doesn't
    # blow out the axis
    hi = pct(reaction, 99)
    shown = [r for r in reaction if r <= hi] or reaction
    n_clip = len(reaction) - len(shown)
    plt.figure(figsize=(7, 5))
    bins = min(30, max(5, len(shown)))
    plt.hist(shown, bins=bins, edgecolor="black")
    p50 = pct(reaction, 50)
    plt.axvline(p50, color="red", linestyle="--", label=f"p50 = {p50:.2f} ms")
    plt.xlabel("Misbehaving-client reaction time (ms)")
    plt.ylabel("Count")
    ttl = "Reaction time of a misbehaving client under honest load"
    if n_clip:
        ttl += f"  ({n_clip} outlier(s) > {hi:.1f} ms not shown)"
    plt.title(ttl)
    plt.legend()
    plt.grid(True, axis="y", linestyle="--", linewidth=0.5)
    plt.tight_layout()
    out = outdir / "attacker_reaction_hist.png"
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"[OK] wrote {out}")

    # box: reaction vs the honest-load check-ins it competes with
    series = [("attacker\nreaction", reaction)]
    if honest_load:
        series.append(("honest-load\ncheck-in", honest_load))
    _boxplot(series, outdir / "attacker_reaction_box.png",
             "Latency (ms)",
             "Misbehaving-client reaction vs honest-load check-in latency")
    return True


def plot_reaction_by_attack(csv_path, outdir, only_ok=False):
    """Test bed 1, mixed-attack view: split the attacker_reaction phase by
    meta.attack and draw a per-attack box plot + bar of medians, plus a table."""
    by_attack = load_reaction_by_attack(csv_path, "attacker_reaction", only_ok)
    by_attack = {a: v for a, v in by_attack.items() if v}
    if len(by_attack) < 2:
        return False  # only meaningful when several attacks are present (mixed run)
    print("[test bed 1] reaction time per attack (mixed run)")
    order = sorted(by_attack, key=lambda a: pct(by_attack[a], 50))
    for a in order:
        print(stat_line(a, by_attack[a]))

    # box plot: one box per attack, ordered by median. Cap the y-axis to a
    # robust bound so a lone flier doesn't squish every box into the floor.
    series = [(f"{a}\n(n={len(by_attack[a])})", by_attack[a]) for a in order]
    ymax = 1.3 * max(pct(by_attack[a], 95) for a in order)
    n_clip = sum(1 for a in order for v in by_attack[a] if v > ymax)
    sub = (f"y-axis capped at {ymax:.1f} ms — {n_clip} flier(s) above not shown"
           if n_clip else None)
    _boxplot(series, outdir / "attacker_reaction_by_attack_box.png",
             "Reaction time (ms)",
             "Misbehaving-client reaction time by attack type, under honest load",
             subtitle=sub, ymax=ymax)

    # bar of p50/p95 per attack
    p50s = [pct(by_attack[a], 50) for a in order]
    p95s = [pct(by_attack[a], 95) for a in order]
    x = range(len(order))
    plt.figure(figsize=(8, 5))
    w = 0.4
    plt.bar([i - w / 2 for i in x], p50s, width=w, label="p50", edgecolor="black")
    plt.bar([i + w / 2 for i in x], p95s, width=w, label="p95", edgecolor="black")
    plt.xticks(list(x), order, rotation=20, ha="right")
    plt.ylabel("Reaction time (ms)")
    plt.title("Reaction time per attack (p50 / p95) under honest load")
    plt.legend()
    plt.grid(True, axis="y", linestyle="--", linewidth=0.5)
    plt.tight_layout()
    out = outdir / "attacker_reaction_by_attack_bar.png"
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"[OK] wrote {out}")
    return True


def plot_honest_under_attack(phases, outdir):
    base = phases.get("checkin_honest_baseline", [])
    under = phases.get("checkin_honest_under_attack", [])
    if not base or not under:
        return False
    print("[test bed 2] honest-latency-under-attack")
    print(stat_line("checkin_honest_baseline", base))
    print(stat_line("checkin_honest_under_attack", under))
    bp50, up50 = pct(base, 50), pct(under, 50)
    ratio = (up50 / bp50) if bp50 else float("inf")
    subtitle = f"p50 {bp50:.1f} ms -> {up50:.1f} ms  ({ratio:.2f}x)"
    print(f"  COLLATERAL IMPACT: {subtitle}")

    # cap y to a robust bound so a lone tail sample doesn't squish both boxes
    ymax = 1.3 * max(pct(base, 95), pct(under, 95))
    n_clip = sum(1 for v in base + under if v > ymax)
    sub = subtitle + (f"   (y capped at {ymax:.1f} ms, {n_clip} flier(s) hidden)"
                      if n_clip else "")
    _boxplot(
        [("baseline\n(no attack)", base), ("under\nattack", under)],
        outdir / "honest_latency_baseline_vs_attack_box.png",
        "Honest check-in latency (ms)",
        "Honest voter check-in latency: baseline vs under attack",
        subtitle=sub, ymax=ymax,
    )
    _cdf(
        [("baseline (no attack)", base), ("under attack", under)],
        outdir / "honest_latency_baseline_vs_attack_cdf.png",
        "Honest check-in latency (ms)",
        "Honest check-in latency CDF: baseline vs under attack",
    )
    return True


def plot_reaction_sweep(phases, outdir):
    """TEST BED 1 sweep: attacker reaction time vs honest load."""
    fam = _family(phases, r"attacker_reaction_load(\d+)")
    if not fam:
        return False
    xs = list(fam)
    p50 = [pct(fam[k], 50) for k in xs]
    p95 = [pct(fam[k], 95) for k in xs]
    print("[test bed 1 sweep] attacker reaction vs honest load")
    print("  load(workers)  n    p50     p95     p99   (ms)")
    for k in xs:
        v = fam[k]
        print(f"  {k:<13} {len(v):<4} {pct(v,50):7.1f} {pct(v,95):7.1f} {pct(v,99):7.1f}")
    plt.figure(figsize=(7, 5))
    plt.plot(xs, p50, marker="o", label="p50")
    plt.plot(xs, p95, marker="s", linestyle="--", label="p95")
    plt.xlabel("Honest background load (concurrent honest workers)")
    plt.ylabel("Misbehaving-client reaction time (ms)")
    plt.title("Attacker reaction time vs honest load")
    plt.grid(True, linestyle="--", linewidth=0.5)
    plt.legend()
    plt.tight_layout()
    out = outdir / "attacker_reaction_vs_load.png"
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"[OK] wrote {out}")
    return True


def plot_honest_sweep(phases, outdir):
    """TEST BED 2 sweep: honest check-in latency vs intensity, attack series vs
    load-matched honest control. Amplification = attack_p50 / control_p50."""
    atk = _family(phases, r"checkin_honest_attack(\d+)")
    ctl = _family(phases, r"checkin_honest_control(\d+)")
    if not atk and not ctl:
        return False
    xs = sorted(set(atk) | set(ctl))

    def ser(fam, p):
        return [pct(fam[k], p) if k in fam and fam[k] else float("nan") for k in xs]

    print("[test bed 2 sweep] honest latency vs intensity (attack vs load-matched control)")
    print("  level  attack_p50  control_p50  amp(p50)  attack_p95  control_p95  (ms)")
    for k in xs:
        ap = pct(atk[k], 50) if k in atk else float("nan")
        cp = pct(ctl[k], 50) if k in ctl else float("nan")
        amp = (ap / cp) if (cp == cp and cp) else float("nan")
        a95 = pct(atk[k], 95) if k in atk else float("nan")
        c95 = pct(ctl[k], 95) if k in ctl else float("nan")
        print(f"  {k:<5} {ap:10.1f} {cp:12.1f} {amp:9.2f} {a95:11.1f} {c95:12.1f}")

    plt.figure(figsize=(8, 5))
    plt.plot(xs, ser(atk, 50), marker="o", color="C3", label="attack p50")
    plt.plot(xs, ser(ctl, 50), marker="o", color="C0",
             label="load-matched control p50")
    plt.plot(xs, ser(atk, 95), marker="s", linestyle="--", color="C3",
             label="attack p95")
    plt.plot(xs, ser(ctl, 95), marker="s", linestyle="--", color="C0",
             label="control p95")
    plt.xlabel("Background intensity (concurrent workers)")
    plt.ylabel("Honest check-in latency (ms)")
    plt.title("Honest check-in latency vs intensity:\nattack vs load-matched honest control")
    plt.grid(True, linestyle="--", linewidth=0.5)
    plt.legend()
    plt.tight_layout()
    out = outdir / "honest_latency_vs_intensity.png"
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"[OK] wrote {out}")
    return True


def main():
    ap = argparse.ArgumentParser(description="Plot the contention test beds.")
    ap.add_argument("csv", type=Path,
                    help="Path to untrusted_latencies.csv "
                         "(e.g. logs/metrics/untrusted_latencies.csv)")
    ap.add_argument("--outdir", type=Path, default=None,
                    help="Where to write PNGs (default: the CSV's directory)")
    ap.add_argument("--only-ok", action="store_true",
                    help="Only include rows whose response parsed (ok=True)")
    args = ap.parse_args()

    if not args.csv.exists():
        raise SystemExit(f"[ERR] CSV not found: {args.csv}")
    outdir = args.outdir or args.csv.parent
    outdir.mkdir(parents=True, exist_ok=True)

    phases = load_phases(args.csv, only_ok=args.only_ok)
    if not phases:
        raise SystemExit(f"[ERR] no latency rows parsed from {args.csv}")
    print(f"phases present: {sorted(phases)}")

    did = [
        plot_attacker_reaction(phases, outdir, args.csv, args.only_ok),  # TB1 single point
        plot_reaction_by_attack(args.csv, outdir, args.only_ok),  # TB1, per-attack (mixed)
        plot_honest_under_attack(phases, outdir),      # test bed 2, single point
        plot_reaction_sweep(phases, outdir),           # test bed 1, sweep curve
        plot_honest_sweep(phases, outdir),             # test bed 2, sweep curves
    ]
    if not any(did):
        print("[WARN] no contention test-bed phases found in this CSV "
              "(expected 'attacker_reaction', "
              "'checkin_honest_baseline'+'checkin_honest_under_attack', or the "
              "sweep families 'attacker_reaction_load{K}' / "
              "'checkin_honest_attack{K}'+'checkin_honest_control{K}').")


if __name__ == "__main__":
    main()
