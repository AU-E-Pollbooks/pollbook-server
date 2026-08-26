# graphs/v2 — paper figures, no embedded titles

Same measurements as `graphs/v1`; the changes are presentational.

The matplotlib title is gone from each figure: in the paper every one of these
is placed in a `figure` environment whose `\caption` sits *below* the image and
already states the same thing, so the embedded title was printed twice.

The throughput figure also loses its legend. It plotted a single series labelled
"Throughput" against a y-axis already reading "Throughput (txn/s)", so the legend
box only covered part of the plot.

Its right edge gained half a unit of padding. The x-limit was hardcoded to
`(0, 20)`, exactly the last data point, so the marker at 20 clients was bisected
by the right spine. The ticks are now pinned as well, because widening the range
made the automatic locator switch to a step of 3 and drop the `20` label.

Axis text is a step up from the matplotlib default (labels 13pt, ticks 11pt)
**on the stress-test figures only**. The three latency figures sit in
`.3\textwidth` minipages, so they are scaled well down on the page and the
default 10pt was small once printed. The contention figures under `contention/`
keep the default font — they run at full column width and did not need it.

These are regenerated from source, not cropped. An earlier attempt trimmed
35 px off the top of the v1 PNGs (1200x750 -> 1200x715), which removed the
title but also took the top plot frame with it — on the throughput figure it
cut the `1.75` y-axis label and clipped the marker at 20 clients. Regenerating
lets `tight_layout()` reflow the axes into the reclaimed space instead.

## Figures

| file | paper caption |
|---|---|
| `throughput_vs_clients.png` | Increase in throughput as the number of clients increase |
| `latency_untrusted_id_service.png` | Median latency of ID-submission phase as the number of clients increases |
| `latency_untrusted_checkin_service.png` | Median latency of untrusted check-in phase as the number of clients increases |
| `latency_trusted_trusted_verify.png` | Median latency of trusted verification phase as the number of clients increases |

## Data

`data/` holds the aggregated values actually plotted, extracted through the
same code path as the figures. Raw per-client logs stay in
`ansible-configs/tests/<N>-clients/`.

- `latency_vs_clients.csv` — `phase,clients,median_ms,p5_ms,p90_ms` (error bars
  are the 5th and 90th percentiles)
- `throughput_vs_clients.csv` — `clients,throughput_txn_per_s`

## Regenerating

Source runs are the 20 units in `ansible-configs/tests/` (2 to 40 total
clients, half untrusted). The x-axis is the untrusted client count, 1 to 20:

```bash
python3 tests/generate_graph.py ansible-configs/tests \
    --x-throughput untrusted_service_count \
    --outdir graphs/v2
```

`--x-throughput untrusted_service_count` is required. The script's default is
`parallel_clients`, which in this dataset is a constant 20 for every run (it is
the harness parallelism setting, not the client count), so the default collapses
all 20 points onto a single x value.


## Contention figures (`contention/`)

The same title removal, applied to the five test-bed figures from
`tests/plot_contention.py`. Fonts are unchanged here.

These carry a small `suptitle` above the title — the y-axis cap and hidden-flier
count, and for test bed 2 the collateral-impact ratio (`p50 1.4 ms -> 1.4 ms
(1.00x)`). **That line is kept.** It states something no caption repeats, and it
is what makes the "honest voters are unaffected" claim readable off the figure.
Only the large descriptive title below it was removed.

| file | paper caption |
|---|---|
| `tb1/attacker_reaction_by_attack_bar.png` | Attacker reaction time by attack type |
| `tb1/attacker_reaction_by_attack_box.png` | Attacker reaction time by attack type (distribution) |
| `tb1/threaded/attacker_reaction_vs_load.png` | Attacker reaction time versus offered load |
| `tb2/honest_latency_baseline_vs_attack_box.png` | Honest-client latency, baseline versus under attack |
| `tb2/honest_latency_baseline_vs_attack_cdf.png` | Honest-client latency CDF, baseline versus under attack |

Four of the five regenerate from `contention/data/tb2_combined.csv`, which holds
both the five-attack `attacker_reaction` breakdown and the
baseline/under-attack pair:

```bash
python3 tests/plot_contention.py graphs/v2/contention/data/tb2_combined.csv \
    --outdir <staging dir>
```

then sort the output into `tb1/` and `tb2/`.

### One caveat on `attacker_reaction_vs_load.png`

Its raw per-sample CSV no longer exists — the threaded sweep's
`attacker_reaction_load{K}` rows are not in any surviving metrics file. The
figure was re-rendered from the per-level summary statistics recorded in
`ansible-configs/logs/untrusted-client-0/run-0001.log`, which is lossless for
this particular figure because it plots only p50 and p95 and the log records
both. Those values are in `contention/data/attacker_reaction_vs_load.csv`.
The result matches the committed original point for point.

Levels 4 and 6 were run but logged `no successful samples`, which is the
connection ceiling at ~3 concurrent clients, so the curve stops at 3.
Re-running the sweep would be needed to regenerate this one from raw samples.
