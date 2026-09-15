#!/usr/bin/env python3
import argparse,csv,glob,os,statistics
ap=argparse.ArgumentParser(); ap.add_argument('results_dir'); ap.add_argument('--mode',default='full'); a=ap.parse_args()
rows=[]
for workload in ['drop','cms','nat','routing','tunnel']:
    vals={}
    for v in ['kfunc','native']:
        p=os.path.join(a.results_dir,f'{workload}_{a.mode}_{v}.csv')
        if not os.path.exists(p): continue
        x=list(csv.DictReader(open(p)))
        vals[v]=(statistics.mean(float(r['mpps']) for r in x), statistics.mean(float(r['ns_per_pkt']) for r in x))
    if len(vals)==2:
        km,kn=vals['kfunc']; nm,nn=vals['native']
        rows.append((workload,km,nm,(nm/km-1)*100,kn,nn,nn-kn,(nn/kn-1)*100))
print('workload,kfunc_mpps,native_mpps,native_gain_pct,kfunc_ns_pkt,native_ns_pkt,delta_ns_pkt,native_ns_pct')
for r in rows: print(','.join([r[0]]+[f'{x:.6f}' for x in r[1:]]))
