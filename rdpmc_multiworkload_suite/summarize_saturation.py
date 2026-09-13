#!/usr/bin/env python3
from __future__ import annotations
import csv
import pathlib
import statistics
import sys


def stats(path: pathlib.Path):
    rows=list(csv.DictReader(path.open()))
    m=[float(r['mpps']) for r in rows]
    n=[float(r['ns_per_pkt']) for r in rows]
    return {
        'mpps': statistics.mean(m),
        'mpps_sd': statistics.stdev(m) if len(m)>1 else 0.0,
        'ns': statistics.mean(n),
        'ns_sd': statistics.stdev(n) if len(n)>1 else 0.0,
    }


def main():
    d=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '.')
    workloads=['drop','nat','routing','tunnel']
    variants=['baseline','native_rdpmc','kfunc_rdpmc']
    out=[]
    print('\nFINAL SATURATION SUMMARY')
    print('workload      baseline(Mpps)   native(Mpps)     kfunc(Mpps)      native_vs_kfunc')
    print('-'*86)
    for w in workloads:
        s={}
        for v in variants:
            p=d/f'{w}_{v}_saturation.csv'
            if not p.exists():
                continue
            s[v]=stats(p)
        if len(s)!=3:
            continue
        gain=(s['native_rdpmc']['mpps']/s['kfunc_rdpmc']['mpps']-1)*100
        print(f"{w:10s}  {s['baseline']['mpps']:8.3f}±{s['baseline']['mpps_sd']:.3f}  "
              f"{s['native_rdpmc']['mpps']:8.3f}±{s['native_rdpmc']['mpps_sd']:.3f}  "
              f"{s['kfunc_rdpmc']['mpps']:8.3f}±{s['kfunc_rdpmc']['mpps_sd']:.3f}  "
              f"{gain:+8.2f}%")
        out.append({
            'workload':w,
            'baseline_mpps_mean':s['baseline']['mpps'],
            'baseline_mpps_stdev':s['baseline']['mpps_sd'],
            'native_mpps_mean':s['native_rdpmc']['mpps'],
            'native_mpps_stdev':s['native_rdpmc']['mpps_sd'],
            'kfunc_mpps_mean':s['kfunc_rdpmc']['mpps'],
            'kfunc_mpps_stdev':s['kfunc_rdpmc']['mpps_sd'],
            'native_vs_kfunc_pct':gain,
            'baseline_nspp_mean':s['baseline']['ns'],
            'native_nspp_mean':s['native_rdpmc']['ns'],
            'kfunc_nspp_mean':s['kfunc_rdpmc']['ns'],
        })
    if out:
        p=d/'summary_saturation.csv'
        with p.open('w', newline='') as f:
            wr=csv.DictWriter(f, fieldnames=out[0].keys())
            wr.writeheader(); wr.writerows(out)
        print(f'\nWrote {p}')

if __name__=='__main__':
    main()
