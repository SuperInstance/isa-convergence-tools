#!/usr/bin/env python3
"""
fleet_compare.py — Fleet-wide ISA convergence analysis.

Compares all 11 FLUX runtimes against the converged ISA,
auto-flags divergences, and generates markdown reports.
"""
from __future__ import annotations

import datetime
from collections import defaultdict
from typing import List, Dict, Tuple, Optional

# Import fleet opcode data
from fleet_opcodes import FLEET_RUNTIMES, FLUX_PY_OPCODES, FLUX_JS_OPCODES
from fleet_opcodes import FLUX_SWARM_OPCODES, FLUX_CORE_OPCODES, FLUX_CUDA_OPCODES
from fleet_opcodes import FLUX_JAVA_OPCODES, FLUX_ZIG_OPCODES, FLUX_VM_TS_OPCODES
from fleet_opcodes import GREENHORN_GO_OPCODES, GREENHORN_JS_OPCODES


# ═══════════════════════════════════════════════════════════════════════════════
# SEMANTIC MATCHING — same operation, different naming
# ═══════════════════════════════════════════════════════════════════════════════

SEMANTIC_ALIASES = {
    "iadd": "add", "isub": "sub", "imul": "mul", "idiv": "div",
    "imod": "mod", "irem": "rem", "iand": "and", "ior": "or",
    "ixor": "xor", "inot": "not", "ishl": "shl", "ishr": "shr",
    "ineg": "neg", "icmp": "cmpeq",
    "confld": "confload", "confst": "confstore",
    "confload": "confld", "confstore": "confst",
    "storeoff": "storeof", "loadoff": "loadof",
    "broadcast": "bcast", "delegate": "deleg",
    "capabilityreq": "caprequire", "caprequire": "capabilityreq",
    "confidence_req": "caprequire", "caprequest": "capabilityreq",
    "cadd": "confadd", "csub": "confsub", "cmul": "confmul",
    "cdiv": "confdiv", "cmerge": "confmerge", "cthresh": "confthreshold",
    "halt_err": "illegal", "halterr": "illegal",
}

# Additional mnemonic equivalences specific to fleet runtimes
FLEET_ALIASES = {
    "addi16": "addi", "subi16": "subi",
    "movi16": "movi",
}


def normalize(m: str) -> str:
    """Normalize a mnemonic for semantic comparison."""
    n = m.lower().replace("_", "").replace(".", "")
    return SEMANTIC_ALIASES.get(n, FLEET_ALIASES.get(n, n))


def opcodes_by_hex(ops: List[dict]) -> Dict[int, dict]:
    """Index opcodes by hex value."""
    return {o["hex"]: o for o in ops}


def opcodes_by_mnemonic(ops: List[dict]) -> Dict[str, dict]:
    """Index opcodes by normalized mnemonic."""
    idx = {}
    for o in ops:
        idx[normalize(o["mnemonic"])] = o
    return idx


# ═══════════════════════════════════════════════════════════════════════════════
# FLEET DATA — all runtime opcodes as flat list
# ═══════════════════════════════════════════════════════════════════════════════

def get_all_fleet_sources() -> Dict[str, List[dict]]:
    """Return a flat dict of runtime name -> opcode list."""
    return {
        "flux-py":         FLUX_PY_OPCODES,
        "flux-js":         FLUX_JS_OPCODES,
        "flux-swarm":      FLUX_SWARM_OPCODES,
        "flux-core":       FLUX_CORE_OPCODES,
        "flux-cuda":       FLUX_CUDA_OPCODES,
        "flux-java":       FLUX_JAVA_OPCODES,
        "flux-zig":        FLUX_ZIG_OPCODES,
        "flux-vm-ts":      FLUX_VM_TS_OPCODES,
        "greenhorn-go":    GREENHORN_GO_OPCODES,
        "greenhorn-js":    GREENHORN_JS_OPCODES,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# CONVERGENCE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

class Divergence:
    """A single divergence finding."""
    def __init__(self, kind: str, hex_code: int, details: str,
                 runtimes: Optional[List[str]] = None):
        self.kind = kind        # "hex_conflict", "missing", "extra", "category_mismatch"
        self.hex_code = hex_code
        self.details = details
        self.runtimes = runtimes or []
    
    def __repr__(self):
        return f"Divergence({self.kind}, 0x{self.hex_code:02X}, {self.details!r})"


def compare_runtime_to_converged(
    runtime_name: str,
    runtime_ops: List[dict],
    converged_ops: List[dict],
) -> Tuple[List[Divergence], Dict[str, int]]:
    """
    Compare a single runtime's opcodes against the converged ISA.
    Returns (divergences, stats).
    """
    rt_by_hex = opcodes_by_hex(runtime_ops)
    cv_by_hex = opcodes_by_hex(converged_ops)
    rt_by_mnem = opcodes_by_mnemonic(runtime_ops)
    cv_by_mnem = opcodes_by_mnemonic(converged_ops)
    
    divergences = []
    matched = 0
    hex_conflicts = 0
    missing_in_runtime = 0
    extra_in_runtime = 0
    semantic_matches = 0
    
    # Check all converged opcodes against runtime
    for code, cv_op in sorted(cv_by_hex.items()):
        if code in rt_by_hex:
            rt_op = rt_by_hex[code]
            if rt_op["mnemonic"] == cv_op["mnemonic"]:
                matched += 1
            elif normalize(rt_op["mnemonic"]) == normalize(cv_op["mnemonic"]):
                # Same operation, different naming convention
                semantic_matches += 1
            else:
                # Hex conflict: same code, different operation!
                divergences.append(Divergence(
                    kind="hex_conflict",
                    hex_code=code,
                    details=f"0x{code:02X}: {runtime_name} has {rt_op['mnemonic']} but converged has {cv_op['mnemonic']}",
                    runtimes=[runtime_name],
                ))
                hex_conflicts += 1
        # else: runtime doesn't implement this opcode — normal for subset runtimes
    
    # Check for runtime opcodes not in converged
    for code, rt_op in sorted(rt_by_hex.items()):
        if code not in cv_by_hex:
            # Check if it's a semantic match elsewhere
            nm = normalize(rt_op["mnemonic"])
            found_semantic = False
            for cv_code, cv_op in cv_by_hex.items():
                if normalize(cv_op["mnemonic"]) == nm:
                    # Same mnemonic exists in converged but at different hex code
                    divergences.append(Divergence(
                        kind="encoding_mismatch",
                        hex_code=code,
                        details=f"{rt_op['mnemonic']}: {runtime_name} uses 0x{code:02X}, converged uses 0x{cv_code:02X}",
                        runtimes=[runtime_name],
                    ))
                    found_semantic = True
                    extra_in_runtime += 1
                    break
            if not found_semantic:
                # Truly unique opcode
                extra_in_runtime += 1
    
    stats = {
        "total_runtime_ops": len(runtime_ops),
        "total_converged_ops": len(converged_ops),
        "exact_matches": matched,
        "semantic_matches": semantic_matches,
        "hex_conflicts": hex_conflicts,
        "missing_in_runtime": len(cv_by_hex) - matched - semantic_matches - hex_conflicts,
        "extra_in_runtime": extra_in_runtime,
        "divergences_found": len(divergences),
    }
    
    return divergences, stats


def fleet_compare(converged_ops: List[dict]) -> Dict[str, dict]:
    """
    Compare all fleet runtimes against the converged ISA.
    Returns a dict of runtime_name -> {"divergences": [...], "stats": {...}}.
    """
    sources = get_all_fleet_sources()
    results = {}
    
    for name, ops in sources.items():
        if not ops:
            results[name] = {"divergences": [], "stats": {"total_runtime_ops": 0}}
            continue
        divs, stats = compare_runtime_to_converged(name, ops, converged_ops)
        results[name] = {"divergences": divs, "stats": stats}
    
    return results


def cross_runtime_compare() -> List[Divergence]:
    """
    Compare all runtimes against each other to find cross-runtime divergences.
    Returns divergences where different runtimes assign different operations
    to the same hex code.
    """
    sources = get_all_fleet_sources()
    active = {k: v for k, v in sources.items() if v}
    all_hex_codes = set()
    for ops in active.values():
        all_hex_codes.update(o["hex"] for o in ops)
    
    divergences = []
    for code in sorted(all_hex_codes):
        assignments = {}
        for name, ops in active.items():
            for o in ops:
                if o["hex"] == code:
                    assignments[name] = o["mnemonic"]
        
        # Group by normalized mnemonic
        groups = defaultdict(list)
        for name, mnem in assignments.items():
            groups[normalize(mnem)].append(name)
        
        if len(groups) == 1:
            # All runtimes agree on this code
            continue
        
        # Find the majority group
        majority_nm = max(groups.keys(), key=lambda k: len(groups[k]))
        minority_groups = {k: v for k, v in groups.items() if k != majority_nm}
        
        for alt_nm, runtimes in sorted(minority_groups.items()):
            divergences.append(Divergence(
                kind="cross_runtime_conflict",
                hex_code=code,
                details=(
                    f"0x{code:02X}: {', '.join(runtimes)} uses {assignments[runtimes[0]]} "
                    f"but majority uses {assignments[groups[majority_nm][0]]}"
                ),
                runtimes=runtimes,
            ))
    
    return divergences


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_markdown_report(
    converged_ops: List[dict],
    output_file: Optional[str] = None,
) -> str:
    """Generate a full markdown convergence report."""
    sources = get_all_fleet_sources()
    results = fleet_compare(converged_ops)
    cross_divs = cross_runtime_compare()
    
    lines = []
    lines.append("# FLUX Fleet ISA Convergence Report")
    lines.append(f"\nGenerated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"\n## Summary")
    lines.append("")
    lines.append("| Runtime | Lang | Opcodes | Exact Match | Semantic | Conflicts | Divergences |")
    lines.append("|---------|------|---------|-------------|----------|-----------|-------------|")
    
    total_ops = 0
    total_conflicts = 0
    total_divergences = 0
    
    for name in sorted(results.keys()):
        r = results[name]
        s = r["stats"]
        runtime_info = FLEET_RUNTIMES.get(name, {})
        lang = runtime_info.get("lang", "?")
        
        if s.get("total_runtime_ops", 0) == 0:
            if runtime_info.get("missing"):
                lines.append(f"| **{name}** | {lang} | — | — | — | — | ⛔ repo not found |")
            else:
                lines.append(f"| {name} | {lang} | — | — | — | — | uses embedded sources |")
            continue
        
        total_ops += s["total_runtime_ops"]
        total_conflicts += s["hex_conflicts"]
        total_divergences += s["divergences_found"]
        
        conflict_flag = f"🔴 {s['hex_conflicts']}" if s["hex_conflicts"] > 0 else "✅ 0"
        div_flag = f"⚠️ {s['divergences_found']}" if s["divergences_found"] > 0 else "✅ 0"
        
        lines.append(
            f"| {name} | {lang} | {s['total_runtime_ops']} "
            f"| {s['exact_matches']} | {s['semantic_matches']} "
            f"| {conflict_flag} | {div_flag} |"
        )
    
    lines.append(f"\n**Totals:** {total_ops} opcodes across {len(results)} runtimes, "
                 f"{total_conflicts} conflicts, {total_divergences} divergences")
    
    # Convergence verdict
    if total_conflicts == 0:
        verdict = "✅ CLEAN — No hex conflicts across any runtime"
    elif total_conflicts <= 3:
        verdict = "🟡 NEAR-CONVERGED — Minor conflicts to resolve"
    elif total_conflicts <= 10:
        verdict = "🟠 IN-PROGRESS — Significant divergences remain"
    else:
        verdict = "🔴 DIVERGED — Major ISA fragmentation detected"
    lines.append(f"\n**Verdict:** {verdict}")
    
    # Detailed divergence findings
    all_divs = []
    for name, r in results.items():
        all_divs.extend(r["divergences"])
    all_divs.extend(cross_divs)
    
    if all_divs:
        lines.append("\n---\n")
        lines.append("## Divergence Details")
        lines.append("")
        
        # Group by kind
        by_kind = defaultdict(list)
        for d in all_divs:
            by_kind[d.kind].append(d)
        
        kind_labels = {
            "hex_conflict": "🔴 Hex Conflicts (same code, different operation)",
            "encoding_mismatch": "🟡 Encoding Mismatches (same op, different code)",
            "cross_runtime_conflict": "🟠 Cross-Runtime Conflicts",
        }
        
        for kind in ["hex_conflict", "encoding_mismatch", "cross_runtime_conflict"]:
            divs = by_kind.get(kind, [])
            if not divs:
                continue
            lines.append(f"### {kind_labels.get(kind, kind)}")
            lines.append("")
            lines.append("| Hex | Details | Runtimes |")
            lines.append("|-----|---------|----------|")
            for d in sorted(divs, key=lambda x: x.hex_code):
                rts = ", ".join(d.runtimes) if d.runtimes else "—"
                lines.append(f"| 0x{d.hex_code:02X} | {d.details} | {rts} |")
            lines.append("")
    
    # Per-runtime opcode coverage matrix
    lines.append("---\n")
    lines.append("## Opcode Coverage Matrix (Core Subset)")
    lines.append("")
    lines.append("Core opcodes that every runtime should implement:")
    lines.append("")
    
    core_opcodes = [
        ("HALT",  "system"), ("NOP", "system"), ("MOV", "move"),
        ("MOVI", "move"),   ("ADD", "arithmetic"), ("SUB", "arithmetic"),
        ("MUL", "arithmetic"), ("DIV", "arithmetic"), ("INC", "arithmetic"),
        ("DEC", "arithmetic"), ("CMP", "compare"),  ("JMP", "control"),
        ("JZ", "control"),   ("JNZ", "control"),   ("PUSH", "stack"),
        ("POP", "stack"),
    ]
    
    runtime_names = sorted(sources.keys())
    header = "| Opcode |" + "|".join(f" {n} " for n in runtime_names) + "|"
    sep = "|--------|" + "|".join("-----" for _ in runtime_names) + "|"
    lines.append(header)
    lines.append(sep)
    
    for mnem, cat in core_opcodes:
        row = f"| {mnem:6s} |"
        for name in runtime_names:
            ops = sources[name]
            if not ops:
                row += " ⛔ |"
                continue
            by_h = opcodes_by_hex(ops)
            by_m = opcodes_by_mnemonic(ops)
            nm = normalize(mnem)
            
            # Check exact hex match (using oracle1 encoding as reference)
            found = False
            for o in ops:
                if normalize(o["mnemonic"]) == nm:
                    found = True
                    break
            row += " ✅ |" if found else " — |"
        lines.append(row)
    
    # ISA Family breakdown
    lines.append("\n---\n")
    lines.append("## ISA Family Breakdown")
    lines.append("")
    lines.append("| Runtime | ISA Family | Notes |")
    lines.append("|---------|------------|-------|")
    for name, info in FLEET_RUNTIMES.items():
        fam = info.get("isa_family", "?")
        lang = info.get("lang", "?")
        if info.get("missing"):
            notes = "Repository not found (404)"
        elif fam == "oracle1":
            notes = "Follows Oracle1 variable-length encoding"
        elif fam == "oracle1-divergent":
            notes = "Oracle1-like with key divergences (HALT=0xFF, string ops)"
        elif fam == "jc1":
            notes = "Follows JetsonClaw1 fixed-format encoding"
        elif fam == "spec":
            notes = "Source of truth — defines oracle1, jc1, converged ISAs"
        else:
            notes = "?"
        lines.append(f"| {name} | {fam} | {notes} |")
    
    lines.append("")
    
    report = "\n".join(lines)
    
    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
    
    return report


# ═══════════════════════════════════════════════════════════════════════════════
# CLI COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_fleet_compare(args, converged_ops: List[dict]):
    """Compare all fleet runtimes against the converged ISA."""
    verbose = args.verbose
    
    results = fleet_compare(converged_ops)
    sources = get_all_fleet_sources()
    
    print("# FLUX Fleet ISA Comparison")
    print(f"\nComparing {len(sources)} runtimes against converged ISA ({len(converged_ops)} opcodes)\n")
    
    # Summary table
    print("| Runtime | Opcodes | Exact | Semantic | Conflicts | Extra |")
    print("|---------|---------|-------|----------|-----------|-------|")
    
    total_conflicts = 0
    for name in sorted(results.keys()):
        r = results[name]
        s = r["stats"]
        if s.get("total_runtime_ops", 0) == 0:
            info = FLEET_RUNTIMES.get(name, {})
            if info.get("missing"):
                print(f"| **{name}** | ⛔ missing | — | — | — | — |")
            else:
                print(f"| {name} | — | — | — | — | — |")
            continue
        
        total_conflicts += s["hex_conflicts"]
        conflict_str = f"🔴 {s['hex_conflicts']}" if s["hex_conflicts"] > 0 else "✅ 0"
        print(
            f"| {name} | {s['total_runtime_ops']} "
            f"| {s['exact_matches']} | {s['semantic_matches']} "
            f"| {conflict_str} | {s['extra_in_runtime']} |"
        )
    
    # Verdict
    if total_conflicts == 0:
        print(f"\n✅ **CLEAN** — No hex conflicts across any runtime")
    else:
        print(f"\n⚠️ **{total_conflicts} conflict(s)** found across fleet")
    
    # Divergence details
    if verbose:
        print("\n---\n### Divergence Details\n")
        all_divs = []
        for name, r in results.items():
            all_divs.extend(r["divergences"])
        
        if all_divs:
            for d in sorted(all_divs, key=lambda x: (x.kind, x.hex_code)):
                rts = f" [{', '.join(d.runtimes)}]" if d.runtimes else ""
                print(f"  - **{d.kind}** 0x{d.hex_code:02X}: {d.details}{rts}")
        else:
            print("  No divergences found!")
    else:
        # Show conflicts even in non-verbose mode
        all_divs = []
        for name, r in results.items():
            all_divs.extend(r["divergences"])
        conflicts = [d for d in all_divs if d.kind == "hex_conflict"]
        if conflicts:
            print(f"\n### Hex Conflicts ({len(conflicts)})")
            for d in sorted(conflicts, key=lambda x: x.hex_code):
                print(f"  - 0x{d.hex_code:02X}: {d.details}")


def cmd_report(args, converged_ops: List[dict]):
    """Generate a markdown convergence report."""
    report = generate_markdown_report(converged_ops, args.output)
    
    if args.output:
        print(f"Report written to: {args.output}")
    else:
        print(report)


def cmd_fleet_list(args):
    """List all fleet runtimes and their opcode counts."""
    sources = get_all_fleet_sources()
    
    print("# FLUX Fleet Runtimes\n")
    print("| Runtime | Language | ISA Family | Opcodes | Status |")
    print("|---------|----------|------------|---------|--------|")
    
    for name, info in sorted(FLEET_RUNTIMES.items()):
        lang = info.get("lang", "?")
        fam = info.get("isa_family", "?")
        ops = sources.get(name, [])
        count = len(ops) if ops else 0
        
        if info.get("missing"):
            status = "⛔ repo not found"
        elif count == 0:
            status = "uses embedded sources"
        else:
            status = "✅ active"
        
        print(f"| {name} | {lang} | {fam} | {count} | {status} |")
