#!/usr/bin/env python3
"""
fleet_opcodes.py — Opcode tables extracted from all 11 FLUX runtime implementations.

Each runtime is a dict with:
  - "name": str (display name)
  - "lang": str (programming language)
  - "repo": str (GitHub repo path)
  - "opcodes": list of {"hex": int, "mnemonic": str, "category": str}

These are extracted directly from the source code of each runtime repository.
"""
from __future__ import annotations
from typing import List, Dict


def _tag(ops: List[dict], source: str) -> List[dict]:
    for o in ops:
        o["source"] = source
        o.setdefault("format", "?")
        o.setdefault("confidence", False)
    return ops


# ── 1. flux-py (Python) — 7 opcodes, oracle1-compatible subset ────────────────
# Source: flux-py/flux_vm.py
FLUX_PY_OPCODES = _tag([
    {"hex": 0x2B, "mnemonic": "MOVI",  "category": "move"},
    {"hex": 0x08, "mnemonic": "IADD",  "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "IMUL",  "category": "arithmetic"},
    {"hex": 0x0B, "mnemonic": "IDIV",  "category": "arithmetic"},
    {"hex": 0x0F, "mnemonic": "DEC",   "category": "arithmetic"},
    {"hex": 0x06, "mnemonic": "JNZ",   "category": "control"},
    {"hex": 0x80, "mnemonic": "HALT",  "category": "system"},
], "flux-py")

# ── 2. flux-js (JavaScript) — 16 opcodes ──────────────────────────────────────
# Source: flux-js/flux.js
FLUX_JS_OPCODES = _tag([
    {"hex": 0x00, "mnemonic": "NOP",   "category": "system"},
    {"hex": 0x01, "mnemonic": "MOV",   "category": "move"},
    {"hex": 0x07, "mnemonic": "JMP",   "category": "control"},
    {"hex": 0x08, "mnemonic": "IADD",  "category": "arithmetic"},
    {"hex": 0x09, "mnemonic": "ISUB",  "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "IMUL",  "category": "arithmetic"},
    {"hex": 0x0B, "mnemonic": "IDIV",  "category": "arithmetic"},
    {"hex": 0x0E, "mnemonic": "INC",   "category": "arithmetic"},
    {"hex": 0x0F, "mnemonic": "DEC",   "category": "arithmetic"},
    {"hex": 0x10, "mnemonic": "PUSH",  "category": "stack"},
    {"hex": 0x11, "mnemonic": "POP",   "category": "stack"},
    {"hex": 0x06, "mnemonic": "JNZ",   "category": "control"},
    {"hex": 0x2E, "mnemonic": "JZ",    "category": "control"},
    {"hex": 0x2B, "mnemonic": "MOVI",  "category": "move"},
    {"hex": 0x2D, "mnemonic": "CMP",   "category": "compare"},
    {"hex": 0x80, "mnemonic": "HALT",  "category": "system"},
], "flux-js")

# ── 3. flux-swarm (Go) — 14 opcodes ───────────────────────────────────────────
# Source: flux-swarm/flux.go
FLUX_SWARM_OPCODES = _tag([
    {"hex": 0x00, "mnemonic": "NOP",   "category": "system"},
    {"hex": 0x01, "mnemonic": "MOV",   "category": "move"},
    {"hex": 0x08, "mnemonic": "IADD",  "category": "arithmetic"},
    {"hex": 0x09, "mnemonic": "ISUB",  "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "IMUL",  "category": "arithmetic"},
    {"hex": 0x0B, "mnemonic": "IDIV",  "category": "arithmetic"},
    {"hex": 0x06, "mnemonic": "JNZ",   "category": "control"},
    {"hex": 0x2E, "mnemonic": "JZ",    "category": "control"},
    {"hex": 0x13, "mnemonic": "JMP",   "category": "control"},
    {"hex": 0x2B, "mnemonic": "MOVI",  "category": "move"},
    {"hex": 0x2D, "mnemonic": "CMP",   "category": "compare"},
    {"hex": 0x0E, "mnemonic": "INC",   "category": "arithmetic"},
    {"hex": 0x0F, "mnemonic": "DEC",   "category": "arithmetic"},
    {"hex": 0x80, "mnemonic": "HALT",  "category": "system"},
], "flux-swarm")

# ── 4. flux-core (Rust) — 23 opcodes, oracle1-compatible ──────────────────────
# Source: flux-core/src/vm/interpreter.rs
FLUX_CORE_OPCODES = _tag([
    {"hex": 0x00, "mnemonic": "NOP",   "category": "system"},
    {"hex": 0x01, "mnemonic": "MOV",   "category": "move"},
    {"hex": 0x04, "mnemonic": "JMP",   "category": "control"},
    {"hex": 0x05, "mnemonic": "JZ",    "category": "control"},
    {"hex": 0x06, "mnemonic": "JNZ",   "category": "control"},
    {"hex": 0x07, "mnemonic": "CALL",  "category": "control"},
    {"hex": 0x08, "mnemonic": "IADD",  "category": "arithmetic"},
    {"hex": 0x09, "mnemonic": "ISUB",  "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "IMUL",  "category": "arithmetic"},
    {"hex": 0x0B, "mnemonic": "IDIV",  "category": "arithmetic"},
    {"hex": 0x0C, "mnemonic": "IMOD",  "category": "arithmetic"},
    {"hex": 0x0D, "mnemonic": "INEG",  "category": "arithmetic"},
    {"hex": 0x0E, "mnemonic": "INC",   "category": "arithmetic"},
    {"hex": 0x0F, "mnemonic": "DEC",   "category": "arithmetic"},
    {"hex": 0x10, "mnemonic": "IAND",  "category": "logic"},
    {"hex": 0x11, "mnemonic": "IOR",   "category": "logic"},
    {"hex": 0x12, "mnemonic": "IXOR",  "category": "logic"},
    {"hex": 0x13, "mnemonic": "INOT",  "category": "logic"},
    {"hex": 0x20, "mnemonic": "PUSH",  "category": "stack"},
    {"hex": 0x21, "mnemonic": "POP",   "category": "stack"},
    {"hex": 0x22, "mnemonic": "DUP",   "category": "stack"},
    {"hex": 0x28, "mnemonic": "RET",   "category": "control"},
    {"hex": 0x2B, "mnemonic": "MOVI",  "category": "move"},
], "flux-core")

# ── 5. flux-cuda (CUDA) — 13 opcodes ─────────────────────────────────────────
# Source: flux-cuda/include/flux_cuda.h
FLUX_CUDA_OPCODES = _tag([
    {"hex": 0x2B, "mnemonic": "MOVI",  "category": "move"},
    {"hex": 0x08, "mnemonic": "IADD",  "category": "arithmetic"},
    {"hex": 0x09, "mnemonic": "ISUB",  "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "IMUL",  "category": "arithmetic"},
    {"hex": 0x0B, "mnemonic": "IDIV",  "category": "arithmetic"},
    {"hex": 0x0E, "mnemonic": "INC",   "category": "arithmetic"},
    {"hex": 0x0F, "mnemonic": "DEC",   "category": "arithmetic"},
    {"hex": 0x2D, "mnemonic": "CMP",   "category": "compare"},
    {"hex": 0x05, "mnemonic": "JZ",    "category": "control"},
    {"hex": 0x06, "mnemonic": "JNZ",   "category": "control"},
    {"hex": 0x04, "mnemonic": "JMP",   "category": "control"},
    {"hex": 0x80, "mnemonic": "HALT",  "category": "system"},
    {"hex": 0x20, "mnemonic": "PUSH",  "category": "stack"},
    {"hex": 0x21, "mnemonic": "POP",   "category": "stack"},
], "flux-cuda")

# ── 6. flux-java (Java) — 15 opcodes ──────────────────────────────────────────
# Source: flux-java/src/main/java/com/superinstance/flux/FluxVM.java
FLUX_JAVA_OPCODES = _tag([
    {"hex": 0x80, "mnemonic": "HALT",  "category": "system"},
    {"hex": 0x01, "mnemonic": "MOV",   "category": "move"},
    {"hex": 0x2B, "mnemonic": "MOVI",  "category": "move"},
    {"hex": 0x08, "mnemonic": "IADD",  "category": "arithmetic"},
    {"hex": 0x09, "mnemonic": "ISUB",  "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "IMUL",  "category": "arithmetic"},
    {"hex": 0x0B, "mnemonic": "IDIV",  "category": "arithmetic"},
    {"hex": 0x0E, "mnemonic": "INC",   "category": "arithmetic"},
    {"hex": 0x0F, "mnemonic": "DEC",   "category": "arithmetic"},
    {"hex": 0x2D, "mnemonic": "CMP",   "category": "compare"},
    {"hex": 0x2E, "mnemonic": "JZ",    "category": "control"},
    {"hex": 0x06, "mnemonic": "JNZ",   "category": "control"},
    {"hex": 0x07, "mnemonic": "JMP",   "category": "control"},
    {"hex": 0x10, "mnemonic": "PUSH",  "category": "stack"},
    {"hex": 0x11, "mnemonic": "POP",   "category": "stack"},
], "flux-java")

# ── 7. flux-zig (Zig) — 15 opcodes ────────────────────────────────────────────
# Source: flux-zig/src/main.zig
FLUX_ZIG_OPCODES = _tag([
    {"hex": 0x01, "mnemonic": "MOV",   "category": "move"},
    {"hex": 0x08, "mnemonic": "IADD",  "category": "arithmetic"},
    {"hex": 0x09, "mnemonic": "ISUB",  "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "IMUL",  "category": "arithmetic"},
    {"hex": 0x0B, "mnemonic": "IDIV",  "category": "arithmetic"},
    {"hex": 0x0E, "mnemonic": "INC",   "category": "arithmetic"},
    {"hex": 0x0F, "mnemonic": "DEC",   "category": "arithmetic"},
    {"hex": 0x10, "mnemonic": "PUSH",  "category": "stack"},
    {"hex": 0x11, "mnemonic": "POP",   "category": "stack"},
    {"hex": 0x2D, "mnemonic": "CMP",   "category": "compare"},
    {"hex": 0x2B, "mnemonic": "MOVI",  "category": "move"},
    {"hex": 0x2E, "mnemonic": "JZ",    "category": "control"},
    {"hex": 0x06, "mnemonic": "JNZ",   "category": "control"},
    {"hex": 0x07, "mnemonic": "JMP",   "category": "control"},
    {"hex": 0x80, "mnemonic": "HALT",  "category": "system"},
], "flux-zig")

# ── 8. flux-runtime (Python, main spec) — already embedded as oracle1/jc1/converged ─
# No separate table needed — use the existing SOURCES entries.

# ── 9. flux-vm-ts (TypeScript) — 56 opcodes, oracle1-like with divergences ─────
# Source: flux-vm-ts/src/opcodes.ts
# NOTE: HALT=0xFF (not 0x80!), PUSH=0x20 (not 0x0C!), unique string ops, PRINT=0xFE
FLUX_VM_TS_OPCODES = _tag([
    # Control flow (0x00-0x07) — matches oracle1
    {"hex": 0x00, "mnemonic": "NOP",   "category": "system"},
    {"hex": 0x01, "mnemonic": "MOV",   "category": "move"},
    {"hex": 0x02, "mnemonic": "LOAD",  "category": "memory"},
    {"hex": 0x03, "mnemonic": "STORE", "category": "memory"},
    {"hex": 0x04, "mnemonic": "JMP",   "category": "control"},
    {"hex": 0x05, "mnemonic": "JZ",    "category": "control"},
    {"hex": 0x06, "mnemonic": "JNZ",   "category": "control"},
    {"hex": 0x07, "mnemonic": "CALL",  "category": "control"},
    # Integer arithmetic (0x08-0x0F) — matches oracle1
    {"hex": 0x08, "mnemonic": "IADD",  "category": "arithmetic"},
    {"hex": 0x09, "mnemonic": "ISUB",  "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "IMUL",  "category": "arithmetic"},
    {"hex": 0x0B, "mnemonic": "IDIV",  "category": "arithmetic"},
    {"hex": 0x0C, "mnemonic": "IMOD",  "category": "arithmetic"},
    {"hex": 0x0D, "mnemonic": "INEG",  "category": "arithmetic"},
    {"hex": 0x0E, "mnemonic": "INC",   "category": "arithmetic"},
    {"hex": 0x0F, "mnemonic": "DEC",   "category": "arithmetic"},
    # Bitwise (0x10-0x17) — matches oracle1
    {"hex": 0x10, "mnemonic": "IAND",  "category": "logic"},
    {"hex": 0x11, "mnemonic": "IOR",   "category": "logic"},
    {"hex": 0x12, "mnemonic": "IXOR",  "category": "logic"},
    {"hex": 0x13, "mnemonic": "INOT",  "category": "logic"},
    {"hex": 0x14, "mnemonic": "ISHL",  "category": "shift"},
    {"hex": 0x15, "mnemonic": "ISHR",  "category": "shift"},
    {"hex": 0x16, "mnemonic": "ROTL",  "category": "shift"},
    {"hex": 0x17, "mnemonic": "ROTR",  "category": "shift"},
    # Comparison (0x18-0x1F) — matches oracle1
    {"hex": 0x18, "mnemonic": "ICMP",  "category": "compare"},
    {"hex": 0x19, "mnemonic": "IEQ",   "category": "compare"},
    {"hex": 0x1A, "mnemonic": "ILT",   "category": "compare"},
    {"hex": 0x1B, "mnemonic": "ILE",   "category": "compare"},
    {"hex": 0x1C, "mnemonic": "IGT",   "category": "compare"},
    {"hex": 0x1D, "mnemonic": "IGE",   "category": "compare"},
    {"hex": 0x1E, "mnemonic": "TEST",  "category": "compare"},
    {"hex": 0x1F, "mnemonic": "SETCC", "category": "compare"},
    # Stack ops (0x20-0x27) — matches oracle1
    {"hex": 0x20, "mnemonic": "PUSH",  "category": "stack"},
    {"hex": 0x21, "mnemonic": "POP",   "category": "stack"},
    {"hex": 0x22, "mnemonic": "DUP",   "category": "stack"},
    {"hex": 0x23, "mnemonic": "SWAP",  "category": "stack"},
    {"hex": 0x24, "mnemonic": "ROT",   "category": "stack"},
    {"hex": 0x25, "mnemonic": "ENTER", "category": "stack"},
    {"hex": 0x26, "mnemonic": "LEAVE", "category": "stack"},
    {"hex": 0x27, "mnemonic": "ALLOCA","category": "memory"},
    # Function ops (0x28-0x2F) — matches oracle1
    {"hex": 0x28, "mnemonic": "RET",      "category": "control"},
    {"hex": 0x29, "mnemonic": "CALL_IND", "category": "control"},
    {"hex": 0x2A, "mnemonic": "TAILCALL", "category": "control"},
    {"hex": 0x2B, "mnemonic": "MOVI",     "category": "move"},
    {"hex": 0x2C, "mnemonic": "IREM",     "category": "arithmetic"},
    {"hex": 0x2D, "mnemonic": "CMP",      "category": "compare"},
    {"hex": 0x2E, "mnemonic": "JE",       "category": "control"},
    {"hex": 0x2F, "mnemonic": "JNE",      "category": "control"},
    # Memory mgmt (0x30-0x37) — matches oracle1
    {"hex": 0x30, "mnemonic": "REGION_CREATE",  "category": "memory"},
    {"hex": 0x31, "mnemonic": "REGION_DESTROY", "category": "memory"},
    {"hex": 0x32, "mnemonic": "REGION_TRANSFER","category": "memory"},
    {"hex": 0x33, "mnemonic": "MEMCOPY",        "category": "memory"},
    {"hex": 0x34, "mnemonic": "MEMSET",         "category": "memory"},
    {"hex": 0x35, "mnemonic": "MEMCMP",         "category": "memory"},
    {"hex": 0x36, "mnemonic": "JL",             "category": "control"},
    {"hex": 0x37, "mnemonic": "JGE",            "category": "control"},
    # Type ops (0x38-0x3C)
    {"hex": 0x38, "mnemonic": "CAST",         "category": "convert"},
    {"hex": 0x39, "mnemonic": "BOX",          "category": "convert"},
    {"hex": 0x3A, "mnemonic": "UNBOX",        "category": "convert"},
    {"hex": 0x3B, "mnemonic": "CHECK_TYPE",   "category": "convert"},
    {"hex": 0x3C, "mnemonic": "CHECK_BOUNDS", "category": "convert"},
    # Float arithmetic (0x40-0x47)
    {"hex": 0x40, "mnemonic": "FADD",  "category": "float"},
    {"hex": 0x41, "mnemonic": "FSUB",  "category": "float"},
    {"hex": 0x42, "mnemonic": "FMUL",  "category": "float"},
    {"hex": 0x43, "mnemonic": "FDIV",  "category": "float"},
    {"hex": 0x44, "mnemonic": "FNEG",  "category": "float"},
    {"hex": 0x45, "mnemonic": "FABS",  "category": "float"},
    {"hex": 0x46, "mnemonic": "FMIN",  "category": "float"},
    {"hex": 0x47, "mnemonic": "FMAX",  "category": "float"},
    # Float comparison (0x48-0x4C)
    {"hex": 0x48, "mnemonic": "FEQ",   "category": "float"},
    {"hex": 0x49, "mnemonic": "FLT",   "category": "float"},
    {"hex": 0x4A, "mnemonic": "FLE",   "category": "float"},
    {"hex": 0x4B, "mnemonic": "FGT",   "category": "float"},
    {"hex": 0x4C, "mnemonic": "FGE",   "category": "float"},
    # String ops (0x50-0x54) — flux-vm-ts exclusive
    {"hex": 0x50, "mnemonic": "SLEN",    "category": "string"},
    {"hex": 0x51, "mnemonic": "SCONCAT", "category": "string"},
    {"hex": 0x52, "mnemonic": "SCHAR",   "category": "string"},
    {"hex": 0x53, "mnemonic": "SSUB",    "category": "string"},
    {"hex": 0x54, "mnemonic": "SCMP",    "category": "string"},
    # A2A Agent Protocol (0x60-0x65)
    {"hex": 0x60, "mnemonic": "TELL",          "category": "a2a"},
    {"hex": 0x61, "mnemonic": "ASK",           "category": "a2a"},
    {"hex": 0x62, "mnemonic": "DELEGATE",      "category": "a2a"},
    {"hex": 0x63, "mnemonic": "BROADCAST",     "category": "a2a"},
    {"hex": 0x64, "mnemonic": "TRUST_CHECK",   "category": "a2a"},
    {"hex": 0x65, "mnemonic": "CAPABILITY_REQ","category": "a2a"},
    # System (0xFE-0xFF)
    {"hex": 0xFE, "mnemonic": "PRINT",  "category": "system"},
    {"hex": 0xFF, "mnemonic": "HALT",   "category": "system"},
], "flux-vm-ts")

# ── 10. greenhorn-runtime Go VM — 30 opcodes, jc1-compatible ──────────────────
# Source: greenhorn-runtime/pkg/flux/vm.go
GREENHORN_GO_OPCODES = _tag([
    {"hex": 0x00, "mnemonic": "HALT",      "category": "system"},
    {"hex": 0x01, "mnemonic": "NOP",       "category": "system"},
    {"hex": 0x02, "mnemonic": "RET",       "category": "system"},
    {"hex": 0x08, "mnemonic": "INC",       "category": "arithmetic"},
    {"hex": 0x09, "mnemonic": "DEC",       "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "NOT",       "category": "logic"},
    {"hex": 0x0B, "mnemonic": "NEG",       "category": "arithmetic"},
    {"hex": 0x0C, "mnemonic": "PUSH",      "category": "stack"},
    {"hex": 0x0D, "mnemonic": "POP",       "category": "stack"},
    {"hex": 0x0E, "mnemonic": "CONF_LOAD", "category": "confidence"},
    {"hex": 0x0F, "mnemonic": "CONF_STORE","category": "confidence"},
    {"hex": 0x17, "mnemonic": "STRIPCONF", "category": "confidence"},
    {"hex": 0x18, "mnemonic": "MOVI",      "category": "move"},
    {"hex": 0x19, "mnemonic": "ADDI",      "category": "arithmetic"},
    {"hex": 0x1A, "mnemonic": "SUBI",      "category": "arithmetic"},
    {"hex": 0x20, "mnemonic": "ADD",       "category": "arithmetic"},
    {"hex": 0x21, "mnemonic": "SUB",       "category": "arithmetic"},
    {"hex": 0x22, "mnemonic": "MUL",       "category": "arithmetic"},
    {"hex": 0x23, "mnemonic": "DIV",       "category": "arithmetic"},
    {"hex": 0x24, "mnemonic": "MOD",       "category": "arithmetic"},
    {"hex": 0x25, "mnemonic": "AND",       "category": "logic"},
    {"hex": 0x26, "mnemonic": "OR",        "category": "logic"},
    {"hex": 0x27, "mnemonic": "XOR",       "category": "logic"},
    {"hex": 0x28, "mnemonic": "SHL",       "category": "shift"},
    {"hex": 0x29, "mnemonic": "SHR",       "category": "shift"},
    {"hex": 0x2A, "mnemonic": "MIN",       "category": "arithmetic"},
    {"hex": 0x2B, "mnemonic": "MAX",       "category": "arithmetic"},
    {"hex": 0x2C, "mnemonic": "CMP_EQ",    "category": "compare"},
    {"hex": 0x2D, "mnemonic": "CMP_LT",    "category": "compare"},
    {"hex": 0x2E, "mnemonic": "CMP_GT",    "category": "compare"},
    {"hex": 0x2F, "mnemonic": "CMP_NE",    "category": "compare"},
    {"hex": 0x3A, "mnemonic": "MOV",       "category": "move"},
    {"hex": 0x3C, "mnemonic": "JZ",        "category": "control"},
    {"hex": 0x3D, "mnemonic": "JNZ",       "category": "control"},
    {"hex": 0x40, "mnemonic": "MOVI16",    "category": "move"},
    {"hex": 0x43, "mnemonic": "JMP",       "category": "control"},
    {"hex": 0x46, "mnemonic": "LOOP",      "category": "control"},
], "greenhorn-go")

# ── 11. greenhorn-runtime JS VM — 23 opcodes, jc1-compatible ──────────────────
# Source: greenhorn-runtime/js/flux_vm.js
GREENHORN_JS_OPCODES = _tag([
    {"hex": 0x00, "mnemonic": "HALT",      "category": "system"},
    {"hex": 0x01, "mnemonic": "NOP",       "category": "system"},
    {"hex": 0x08, "mnemonic": "INC",       "category": "arithmetic"},
    {"hex": 0x09, "mnemonic": "DEC",       "category": "arithmetic"},
    {"hex": 0x0A, "mnemonic": "NOT",       "category": "logic"},
    {"hex": 0x0B, "mnemonic": "NEG",       "category": "arithmetic"},
    {"hex": 0x0C, "mnemonic": "PUSH",      "category": "stack"},
    {"hex": 0x0D, "mnemonic": "POP",       "category": "stack"},
    {"hex": 0x17, "mnemonic": "STRIPCONF", "category": "confidence"},
    {"hex": 0x18, "mnemonic": "MOVI",      "category": "move"},
    {"hex": 0x19, "mnemonic": "ADDI",      "category": "arithmetic"},
    {"hex": 0x1A, "mnemonic": "SUBI",      "category": "arithmetic"},
    {"hex": 0x20, "mnemonic": "ADD",       "category": "arithmetic"},
    {"hex": 0x21, "mnemonic": "SUB",       "category": "arithmetic"},
    {"hex": 0x22, "mnemonic": "MUL",       "category": "arithmetic"},
    {"hex": 0x23, "mnemonic": "DIV",       "category": "arithmetic"},
    {"hex": 0x2A, "mnemonic": "MIN",       "category": "arithmetic"},
    {"hex": 0x2B, "mnemonic": "MAX",       "category": "arithmetic"},
    {"hex": 0x2C, "mnemonic": "CMP_EQ",    "category": "compare"},
    {"hex": 0x2D, "mnemonic": "CMP_LT",    "category": "compare"},
    {"hex": 0x3A, "mnemonic": "MOV",       "category": "move"},
    {"hex": 0x40, "mnemonic": "MOVI16",    "category": "move"},
    {"hex": 0x43, "mnemonic": "JMP",       "category": "control"},
    {"hex": 0x46, "mnemonic": "LOOP",      "category": "control"},
], "greenhorn-js")


# ═══════════════════════════════════════════════════════════════════════════════
# FLEET REGISTRY — All 11 runtimes (+ 1 missing)
# ═══════════════════════════════════════════════════════════════════════════════

FLEET_RUNTIMES: Dict[str, dict] = {
    "flux-py": {
        "name": "flux-py",
        "lang": "Python",
        "repo": "SuperInstance/flux-py",
        "opcodes": FLUX_PY_OPCODES,
        "isa_family": "oracle1",     # follows oracle1 encoding
    },
    "flux-js": {
        "name": "flux-js",
        "lang": "JavaScript",
        "repo": "SuperInstance/flux-js",
        "opcodes": FLUX_JS_OPCODES,
        "isa_family": "oracle1",
    },
    "flux-swarm": {
        "name": "flux-swarm",
        "lang": "Go",
        "repo": "SuperInstance/flux-swarm",
        "opcodes": FLUX_SWARM_OPCODES,
        "isa_family": "oracle1",
    },
    "flux-core": {
        "name": "flux-core",
        "lang": "Rust",
        "repo": "SuperInstance/flux-core",
        "opcodes": FLUX_CORE_OPCODES,
        "isa_family": "oracle1",
    },
    "flux-cuda": {
        "name": "flux-cuda",
        "lang": "CUDA/C++",
        "repo": "SuperInstance/flux-cuda",
        "opcodes": FLUX_CUDA_OPCODES,
        "isa_family": "oracle1",
    },
    "flux-c": {
        "name": "flux-c",
        "lang": "C",
        "repo": "SuperInstance/flux-c",
        "opcodes": [],  # repo not found (404)
        "isa_family": "unknown",
        "missing": True,
    },
    "flux-java": {
        "name": "flux-java",
        "lang": "Java",
        "repo": "SuperInstance/flux-java",
        "opcodes": FLUX_JAVA_OPCODES,
        "isa_family": "oracle1",
    },
    "flux-zig": {
        "name": "flux-zig",
        "lang": "Zig",
        "repo": "SuperInstance/flux-zig",
        "opcodes": FLUX_ZIG_OPCODES,
        "isa_family": "oracle1",
    },
    "flux-runtime": {
        "name": "flux-runtime",
        "lang": "Python",
        "repo": "SuperInstance/flux-runtime",
        "opcodes": [],  # use embedded oracle1/jc1/converged
        "isa_family": "spec",
    },
    "flux-vm-ts": {
        "name": "flux-vm-ts",
        "lang": "TypeScript",
        "repo": "SuperInstance/flux-vm-ts",
        "opcodes": FLUX_VM_TS_OPCODES,
        "isa_family": "oracle1-divergent",  # oracle1-like but with key divergences
    },
    "greenhorn-runtime": {
        "name": "greenhorn-runtime",
        "lang": "Go/JS/Rust",
        "repo": "SuperInstance/greenhorn-runtime",
        "opcodes": [],  # has both greenhorn-go and greenhorn-js
        "isa_family": "jc1",
    },
}
