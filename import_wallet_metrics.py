#!/usr/bin/env python3
"""Imports the GLOVEBOX_METRIC lines of the wallet's XCTest run into the paper.

The wallet test suite (GloveboxWalletTests) prints one JSON line per metric and
keeps each line as a test attachment. This script reads those lines from an
.xcresult bundle (via xcresulttool) or from a directory of exported attachments,
stores them as results/wallet_<tag>.json, and writes tables/tab_wallet.tex and
sections/generated_wallet.tex for the paper.

Usage:
  python3 import_wallet_metrics.py device.xcresult --tag ios --config Release --paper ../paper
"""

import argparse
import json
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LINE = re.compile(r"GLOVEBOX_METRIC (\{.*\})")
MODELS = ["hotel-checkin", "hotel-checkout", "transit-ticket", "transit-inspection", "student-status"]
LABELS = {"hotel-checkin": "Hotel check-in", "hotel-checkout": "Hotel checkout",
          "transit-ticket": "Transit ticket", "transit-inspection": "Ticket inspection",
          "student-status": "Student status"}
DEVICES = {"iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max", "iPhone15,2": "iPhone 14 Pro",
           "iPhone16,1": "iPhone 15 Pro", "iPhone17,1": "iPhone 16 Pro", "iPhone17,3": "iPhone 16",
           "iPhone18,1": "iPhone 17 Pro"}


def collect_lines(source: Path):
    if source.suffix == ".xcresult":
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["xcrun", "xcresulttool", "export", "attachments", "--path", str(source),
                            "--output-path", tmp], check=True, capture_output=True)
            yield from collect_lines(Path(tmp))
        return
    for path in sorted(source.rglob("*.txt")):
        for match in LINE.finditer(path.read_text(errors="replace")):
            yield json.loads(match.group(1))


def max_cv(metrics):
    """Largest standard deviation relative to the median over the wallet's core measurements
    (validation, installation, driver step, prototype engine, BBS+); the SD-JWT presentation is
    reported separately because its library path is the noisiest operation."""
    ratios = []
    for p in metrics["packages"].values():
        for k in ("validate", "install"):
            if f"{k}StdUs" in p:
                ratios.append(p[f"{k}StdUs"] / p[f"{k}MedianUs"])
    st = metrics.get("driverStep", {})
    if "stdUs" in st:
        ratios.append(st["stdUs"] / st["medianUs"])
    pe = metrics.get("prototypeEngine", {})
    for k in ("install", "step"):
        if f"{k}StdUs" in pe:
            ratios.append(pe[f"{k}StdUs"] / pe[f"{k}MedianUs"])
    ops = metrics.get("credentialOps", {})
    for k in ("es256Sign", "bbsProof", "bbsVerify"):
        if f"{k}StdUs" in ops:
            ratios.append(ops[f"{k}StdUs"] / ops[f"{k}MedianUs"])
    return max(ratios) if ratios else 0.0


def core_cv(metrics):
    """Largest σ/median over validation, installation, the driver step, and the BBS+ operations."""
    ratios = []
    for p in metrics["packages"].values():
        for k in ("validate", "install"):
            if f"{k}StdUs" in p:
                ratios.append(p[f"{k}StdUs"] / p[f"{k}MedianUs"])
    st = metrics.get("driverStep", {})
    if "stdUs" in st:
        ratios.append(st["stdUs"] / st["medianUs"])
    ops = metrics.get("credentialOps", {})
    for k in ("bbsProof", "bbsVerify", "sdjwtPresent"):
        if f"{k}StdUs" in ops:
            ratios.append(ops[f"{k}StdUs"] / ops[f"{k}MedianUs"])
    return max(ratios) if ratios else 0.0


def fmt_int(n):
    return f"{n:,}".replace(",", "{,}")


def us(x):
    return f"{x:.0f}" if x >= 10 else f"{x:.1f}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sources", nargs="+", type=Path)
    parser.add_argument("--tag", default="ios")
    parser.add_argument("--config", default="Release", help="Xcode build configuration of the test run")
    parser.add_argument("--paper", type=Path, default=None)
    args = parser.parse_args()

    metrics = {"packages": {}, "stress": {}}
    for source in args.sources:
        for entry in collect_lines(source):
            kind = entry.pop("metric")
            if kind in ("package", "stress"):
                metrics[kind + ("s" if kind == "package" else "")][entry.pop("name")] = entry
            else:
                metrics[kind] = entry
    missing = [m for m in MODELS if m not in metrics["packages"]]
    if missing or "device" not in metrics:
        sys.exit(f"incomplete metrics: missing {missing or 'device'}")
    metrics["config"] = args.config
    device = metrics["device"]
    device["marketingName"] = DEVICES.get(device["model"], device["model"])
    if device.get("simulator"):
        device["marketingName"] += " simulator"

    (ROOT / "results").mkdir(exist_ok=True)
    out = ROOT / "results" / f"wallet_{args.tag}.json"
    out.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out}")
    for name in MODELS:
        p = metrics["packages"][name]
        print(f"  {name:20s} validate {p['validateMedianUs']:.0f}/{p['validateP95Us']:.0f} us "
              f"install {p['installMedianUs']:.0f}/{p['installP95Us']:.0f} us "
              f"advance {p['advancePerTransitionUs']:.2f} us/transition run {p['runSuccessPathMedianUs']:.1f} us")
    for name, v in sorted(metrics["stress"].items(), key=lambda kv: kv[1]["states"]):
        print(f"  stress {name:28s} states={v['states']:5d} validate {v['validateMedianUs']:.0f} us")
    if "credentialOps" in metrics:
        o = metrics["credentialOps"]
        print(f"  credential ops: es256 {o['es256SignMedianUs']:.0f} us, sd-jwt present {o['sdjwtPresentMedianUs']:.0f} us, "
              f"bbs proof {o['bbsProofMedianUs']:.0f} us, bbs verify {o['bbsVerifyMedianUs']:.0f} us")
    if "prototypeEngine" in metrics:
        pe = metrics["prototypeEngine"]
        print(f"  prototype engine: store statechart {pe['installMedianUs']:.0f} us, forced step {pe['stepMedianUs']:.0f} us "
              f"({pe['statechartBytes']} B, {pe['states']} states)")
    print(f"  max CV over core measurements: {100 * max_cv(metrics):.0f}%")
    step = metrics["driverStep"]
    print(f"  driver step {step['medianUs']:.0f}/{step['p95Us']:.0f} us, start {step['startMedianUs']:.0f} us, "
          f"verify {metrics['ed25519Verify']['medianUs']:.0f} us, vectors {metrics['vectors']['agreeing']}/"
          f"{metrics['vectors']['total']}, paths {metrics['pathReplay']['agreeing']}/{metrics['pathReplay']['replayed']}")
    if not args.paper:
        return 0

    tables = args.paper / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in MODELS:
        p = metrics["packages"][name]
        rows.append(f"{LABELS[name]} & {p['states']} & {fmt_int(p['jwsBytes'])} & "
                    f"{us(p['validateMedianUs'])} & {us(p['validateP95Us'])} & "
                    f"{us(p['installMedianUs'])} & {us(p['installP95Us'])} & "
                    f"{p['transitions']} & {us(p['runSuccessPathMedianUs'])} \\\\")
    where = f"{device['marketingName']} (iOS {device['os']})"
    (tables / "tab_wallet.tex").write_text(
        "% Generated by artifact/import_wallet_metrics.py -- do not edit by hand.\n"
        "\\begin{table}[t]\n\\centering\n\\small\n"
        f"\\caption{{Cost inside the iOS wallet on an {where}, {args.config.lower()} build, in $\\mu$s. "
        "Install: validation plus floor ratchet and persistence. Run: the success path of $|\\pi|$ "
        "transitions through the runtime with instant handlers.}\n"
        "\\label{tab:wallet}\n\\setlength{\\tabcolsep}{3pt}\n"
        "\\begin{tabular}{@{}lrrrrrrrr@{}}\n\\toprule\n"
        " & & & \\multicolumn{2}{c}{Validate} & \\multicolumn{2}{c}{Install} & \\multicolumn{2}{c}{Run} \\\\\n"
        "\\cmidrule(lr){4-5}\\cmidrule(lr){6-7}\\cmidrule(l){8-9}\n"
        "Process & $|S|$ & Bytes & med. & p95 & med. & p95 & $|\\pi|$ & med. \\\\\n\\midrule\n"
        + "\n".join(rows) +
        "\n\\bottomrule\n\\end{tabular}\n\\end{table}\n")

    pk = metrics["packages"]
    advance = [pk[n]["advancePerTransitionUs"] for n in MODELS]
    macros = {
        "walletDevice": device["marketingName"],
        "walletOS": device["os"],
        "walletBuild": args.config.lower(),
        "walletValidateMinUs": us(min(pk[n]["validateMedianUs"] for n in MODELS)),
        "walletValidateMaxUs": us(max(pk[n]["validateMedianUs"] for n in MODELS)),
        "walletValidateMaxPNinetyFiveUs": us(max(pk[n]["validateP95Us"] for n in MODELS)),
        "walletInstallMaxUs": us(max(pk[n]["installMedianUs"] for n in MODELS)),
        "walletInstallMaxPNinetyFiveUs": us(max(pk[n]["installP95Us"] for n in MODELS)),
        "walletAdvanceUs": f"{statistics.median(advance):.1f}",
        "walletAdvanceMaxUs": f"{max(advance):.1f}",
        "walletRunMaxUs": us(max(pk[n]["runSuccessPathMedianUs"] for n in MODELS)),
        "walletDriverStepUs": us(step["medianUs"]),
        "walletDriverStepPNinetyFiveUs": us(step["p95Us"]),
        "walletDriverStartUs": us(step["startMedianUs"]),
        "walletDriverStepMs": f"{step['medianUs'] / 1000:.1f}",
        "walletDriverStepPNinetyFiveMs": f"{step['p95Us'] / 1000:.1f}",
        "walletDriverStartMs": f"{step['startMedianUs'] / 1000:.1f}",
        "walletVerifyUs": us(metrics["ed25519Verify"]["medianUs"]),
        "walletVectors": f"{metrics['vectors']['agreeing']}/{metrics['vectors']['total']}",
        "walletVectorsTotal": metrics["vectors"]["total"],
        "walletPaths": f"{metrics['pathReplay']['agreeing']}/{metrics['pathReplay']['replayed']}",
        "walletCheckinValidateUs": us(pk["hotel-checkin"]["validateMedianUs"]),
        "walletCheckinInstallUs": us(pk["hotel-checkin"]["installMedianUs"]),
        "walletProtoInstallUs": us(metrics["prototypeEngine"]["installMedianUs"]) if "prototypeEngine" in metrics else "--",
        "walletProtoStepUs": us(metrics["prototypeEngine"]["stepMedianUs"]) if "prototypeEngine" in metrics else "--",
        "walletProtoStatechartKB": f"{metrics['prototypeEngine']['statechartBytes'] / 1000:.1f}" if "prototypeEngine" in metrics else "--",
        "walletInstallFactor": f"{pk['hotel-checkin']['installMedianUs'] / metrics['prototypeEngine']['installMedianUs']:.1f}" if "prototypeEngine" in metrics else "--",
        "walletInstallInverse": f"{metrics['prototypeEngine']['installMedianUs'] / pk['hotel-checkin']['installMedianUs']:.1f}" if "prototypeEngine" in metrics else "--",
        "walletProtoStepStdUs": f"{metrics['prototypeEngine']['stepStdUs']:.0f}" if "prototypeEngine" in metrics else "--",
        "walletStepFactor": f"{step['medianUs'] / metrics['prototypeEngine']['stepMedianUs']:.1f}" if "prototypeEngine" in metrics else "--",
        "walletMaxCvPercent": f"{100 * max_cv(metrics):.0f}",
        "walletCoreCvPercent": f"{100 * core_cv(metrics):.0f}",
        "walletProtoStepCvPercent": f"{100 * metrics['prototypeEngine']['stepStdUs'] / metrics['prototypeEngine']['stepMedianUs']:.0f}" if "prototypeEngine" in metrics else "--",
        "walletEsCvPercent": f"{100 * metrics.get('credentialOps', {}).get('es256SignStdUs', 0) / max(metrics.get('credentialOps', {}).get('es256SignMedianUs', 1), 1):.0f}",
        "walletSdjwtCvPercent": f"{100 * metrics.get('credentialOps', {}).get('sdjwtPresentStdUs', 0) / max(metrics.get('credentialOps', {}).get('sdjwtPresentMedianUs', 1), 1):.0f}",
        "walletMeasuredOn": ("on an iPhone simulator on the development machine rather than on a phone"
                             if device.get("simulator") else "on one phone model"),
        "walletMeasuredOnShort": ("the wallet ran in an iPhone simulator on the development machine, not on a phone"
                                  if device.get("simulator") else "the wallet ran on one phone model"),
        "walletWhere": ("in the simulator" if device.get("simulator") else "on the phone"),
    }
    (args.paper / "sections" / "generated_wallet.tex").write_text(
        "% Generated by artifact/import_wallet_metrics.py -- do not edit by hand.\n"
        + "".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in macros.items()))
    print(f"wrote {tables / 'tab_wallet.tex'} and sections/generated_wallet.tex")
    return 0


if __name__ == "__main__":
    sys.exit(main())
