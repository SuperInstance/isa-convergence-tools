#!/usr/bin/env python3
"""
flux-isa-diff — ISA Convergence CLI Tool

Compare, diff, and analyze FLUX ISA definitions across the SuperInstance fleet.

Embedded sources:
  - oracle1    : Oracle1's Python VM (opcodes.py, ~80 opcodes, variable-length)
  - jc1        : JetsonClaw1's C VM (unified opcodes, formats.py, ~67 opcodes)
  - babel      : Babel's multilingual (120 opcodes including 16 viewpoint ops)
  - converged  : isa_unified.py (247 opcodes — the target unified ISA)

Fleet runtimes (10 active + 1 missing):
  - flux-py, flux-js, flux-swarm, flux-core, flux-cuda, flux-java, flux-zig,
    flux-vm-ts, greenhorn-runtime (Go+JS), flux-c (missing)

Usage:
  flux-isa-diff list [--source SOURCE] [--category CAT] [--format FMT]
  flux-isa-diff diff <source1> <source2>
  flux-isa-diff stats [--source SOURCE]
  flux-isa-diff converge
  flux-isa-diff verify
  flux-isa-diff fleet-compare [--verbose]      # Compare all 11 runtimes vs converged ISA
  flux-isa-diff fleet-list                  # List all fleet runtimes
  flux-isa-diff report [--output FILE]         # Generate markdown convergence report

Zero dependencies — Python stdlib only.
"""

from __future__ import annotations

import sys
import argparse
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Optional, Set


# ═══════════════════════════════════════════════════════════════════════════════
# ISA DATA — Embedded from fleet sources
# ═══════════════════════════════════════════════════════════════════════════════
# Each source is a list of dicts:
#   { "hex": int, "mnemonic": str, "format": str, "category": str,
#     "description": str, "confidence": bool }
# The converged source additionally has: "source": str (originating agent)


# ── Source: oracle1 (Python VM — opcodes.py, ~80 opcodes) ─────────────────────

ORACLE1_OPCODES: List[dict] = [
    # Control flow (0x00-0x07)
    {"hex": 0x00, "mnemonic": "NOP",         "format": "A", "category": "control",   "description": "No operation"},
    {"hex": 0x01, "mnemonic": "MOV",         "format": "C", "category": "move",      "description": "Register move rd=rs1"},
    {"hex": 0x02, "mnemonic": "LOAD",        "format": "C", "category": "memory",    "description": "Load from memory"},
    {"hex": 0x03, "mnemonic": "STORE",       "format": "C", "category": "memory",    "description": "Store to memory"},
    {"hex": 0x04, "mnemonic": "JMP",         "format": "D", "category": "control",   "description": "Unconditional jump"},
    {"hex": 0x05, "mnemonic": "JZ",          "format": "D", "category": "control",   "description": "Jump if zero"},
    {"hex": 0x06, "mnemonic": "JNZ",         "format": "D", "category": "control",   "description": "Jump if not zero"},
    {"hex": 0x07, "mnemonic": "CALL",        "format": "D", "category": "control",   "description": "Call subroutine"},
    # Integer arithmetic (0x08-0x0F)
    {"hex": 0x08, "mnemonic": "IADD",        "format": "E", "category": "arithmetic","description": "Integer add"},
    {"hex": 0x09, "mnemonic": "ISUB",        "format": "E", "category": "arithmetic","description": "Integer subtract"},
    {"hex": 0x0A, "mnemonic": "IMUL",        "format": "E", "category": "arithmetic","description": "Integer multiply"},
    {"hex": 0x0B, "mnemonic": "IDIV",        "format": "E", "category": "arithmetic","description": "Integer divide"},
    {"hex": 0x0C, "mnemonic": "IMOD",        "format": "E", "category": "arithmetic","description": "Integer modulo"},
    {"hex": 0x0D, "mnemonic": "INEG",        "format": "B", "category": "arithmetic","description": "Integer negate"},
    {"hex": 0x0E, "mnemonic": "INC",         "format": "B", "category": "arithmetic","description": "Increment"},
    {"hex": 0x0F, "mnemonic": "DEC",         "format": "B", "category": "arithmetic","description": "Decrement"},
    # Bitwise (0x10-0x17)
    {"hex": 0x10, "mnemonic": "IAND",        "format": "E", "category": "logic",     "description": "Bitwise AND"},
    {"hex": 0x11, "mnemonic": "IOR",         "format": "E", "category": "logic",     "description": "Bitwise OR"},
    {"hex": 0x12, "mnemonic": "IXOR",        "format": "E", "category": "logic",     "description": "Bitwise XOR"},
    {"hex": 0x13, "mnemonic": "INOT",        "format": "B", "category": "logic",     "description": "Bitwise NOT"},
    {"hex": 0x14, "mnemonic": "ISHL",        "format": "E", "category": "shift",     "description": "Shift left"},
    {"hex": 0x15, "mnemonic": "ISHR",        "format": "E", "category": "shift",     "description": "Shift right"},
    {"hex": 0x16, "mnemonic": "ROTL",        "format": "E", "category": "shift",     "description": "Rotate left"},
    {"hex": 0x17, "mnemonic": "ROTR",        "format": "E", "category": "shift",     "description": "Rotate right"},
    # Comparison (0x18-0x1F)
    {"hex": 0x18, "mnemonic": "ICMP",        "format": "C", "category": "compare",   "description": "Integer compare"},
    {"hex": 0x19, "mnemonic": "IEQ",         "format": "C", "category": "compare",   "description": "Integer equal"},
    {"hex": 0x1A, "mnemonic": "ILT",         "format": "C", "category": "compare",   "description": "Integer less than"},
    {"hex": 0x1B, "mnemonic": "ILE",         "format": "C", "category": "compare",   "description": "Integer less or equal"},
    {"hex": 0x1C, "mnemonic": "IGT",         "format": "C", "category": "compare",   "description": "Integer greater than"},
    {"hex": 0x1D, "mnemonic": "IGE",         "format": "C", "category": "compare",   "description": "Integer greater or equal"},
    {"hex": 0x1E, "mnemonic": "TEST",        "format": "C", "category": "compare",   "description": "Test bits"},
    {"hex": 0x1F, "mnemonic": "SETCC",       "format": "C", "category": "compare",   "description": "Set condition code"},
    # Stack ops (0x20-0x27)
    {"hex": 0x20, "mnemonic": "PUSH",        "format": "B", "category": "stack",     "description": "Push register"},
    {"hex": 0x21, "mnemonic": "POP",         "format": "B", "category": "stack",     "description": "Pop register"},
    {"hex": 0x22, "mnemonic": "DUP",         "format": "A", "category": "stack",     "description": "Duplicate stack top"},
    {"hex": 0x23, "mnemonic": "SWAP",        "format": "A", "category": "stack",     "description": "Swap stack elements"},
    {"hex": 0x24, "mnemonic": "ROT",         "format": "A", "category": "stack",     "description": "Rotate stack elements"},
    {"hex": 0x25, "mnemonic": "ENTER",       "format": "B", "category": "stack",     "description": "Enter frame"},
    {"hex": 0x26, "mnemonic": "LEAVE",       "format": "B", "category": "stack",     "description": "Leave frame"},
    {"hex": 0x27, "mnemonic": "ALLOCA",      "format": "C", "category": "memory",    "description": "Allocate on stack"},
    # Function ops (0x28-0x2F)
    {"hex": 0x28, "mnemonic": "RET",         "format": "C", "category": "control",   "description": "Return from subroutine"},
    {"hex": 0x29, "mnemonic": "CALL_IND",    "format": "C", "category": "control",   "description": "Indirect call"},
    {"hex": 0x2A, "mnemonic": "TAILCALL",    "format": "C", "category": "control",   "description": "Tail call"},
    {"hex": 0x2B, "mnemonic": "MOVI",        "format": "D", "category": "move",      "description": "Move immediate"},
    {"hex": 0x2C, "mnemonic": "IREM",        "format": "E", "category": "arithmetic","description": "Integer remainder"},
    {"hex": 0x2D, "mnemonic": "CMP",         "format": "C", "category": "compare",   "description": "Compare"},
    {"hex": 0x2E, "mnemonic": "JE",          "format": "D", "category": "control",   "description": "Jump if equal"},
    {"hex": 0x2F, "mnemonic": "JNE",         "format": "D", "category": "control",   "description": "Jump if not equal"},
    # Memory mgmt (0x30-0x37)
    {"hex": 0x30, "mnemonic": "REGION_CREATE","format": "G", "category": "memory",    "description": "Create memory region"},
    {"hex": 0x31, "mnemonic": "REGION_DESTROY","format":"G", "category": "memory",    "description": "Destroy memory region"},
    {"hex": 0x32, "mnemonic": "REGION_TRANSFER","format":"G","category": "memory",    "description": "Transfer memory region"},
    {"hex": 0x33, "mnemonic": "MEMCOPY",     "format": "G", "category": "memory",    "description": "Copy memory"},
    {"hex": 0x34, "mnemonic": "MEMSET",      "format": "G", "category": "memory",    "description": "Fill memory"},
    {"hex": 0x35, "mnemonic": "MEMCMP",      "format": "G", "category": "memory",    "description": "Compare memory"},
    {"hex": 0x36, "mnemonic": "JL",          "format": "D", "category": "control",   "description": "Jump if less"},
    {"hex": 0x37, "mnemonic": "JGE",         "format": "D", "category": "control",   "description": "Jump if greater or equal"},
    # Type ops (0x38-0x3F)
    {"hex": 0x38, "mnemonic": "CAST",        "format": "C", "category": "convert",   "description": "Type cast"},
    {"hex": 0x39, "mnemonic": "BOX",         "format": "C", "category": "convert",   "description": "Box value"},
    {"hex": 0x3A, "mnemonic": "UNBOX",       "format": "C", "category": "convert",   "description": "Unbox value"},
    {"hex": 0x3B, "mnemonic": "CHECK_TYPE",  "format": "C", "category": "convert",   "description": "Type check"},
    {"hex": 0x3C, "mnemonic": "CHECK_BOUNDS","format": "C", "category": "convert",   "description": "Bounds check"},
    # Float arithmetic (0x40-0x47)
    {"hex": 0x40, "mnemonic": "FADD",        "format": "E", "category": "float",     "description": "Float add"},
    {"hex": 0x41, "mnemonic": "FSUB",        "format": "E", "category": "float",     "description": "Float subtract"},
    {"hex": 0x42, "mnemonic": "FMUL",        "format": "E", "category": "float",     "description": "Float multiply"},
    {"hex": 0x43, "mnemonic": "FDIV",        "format": "E", "category": "float",     "description": "Float divide"},
    {"hex": 0x44, "mnemonic": "FNEG",        "format": "B", "category": "float",     "description": "Float negate"},
    {"hex": 0x45, "mnemonic": "FABS",        "format": "B", "category": "float",     "description": "Float absolute"},
    {"hex": 0x46, "mnemonic": "FMIN",        "format": "E", "category": "float",     "description": "Float min"},
    {"hex": 0x47, "mnemonic": "FMAX",        "format": "E", "category": "float",     "description": "Float max"},
    # Float comparison (0x48-0x4F)
    {"hex": 0x48, "mnemonic": "FEQ",         "format": "C", "category": "float",     "description": "Float equal"},
    {"hex": 0x49, "mnemonic": "FLT",         "format": "C", "category": "float",     "description": "Float less than"},
    {"hex": 0x4A, "mnemonic": "FLE",         "format": "C", "category": "float",     "description": "Float less or equal"},
    {"hex": 0x4B, "mnemonic": "FGT",         "format": "C", "category": "float",     "description": "Float greater than"},
    {"hex": 0x4C, "mnemonic": "FGE",         "format": "C", "category": "float",     "description": "Float greater or equal"},
    {"hex": 0x4D, "mnemonic": "JG",          "format": "D", "category": "control",   "description": "Jump if greater"},
    {"hex": 0x4E, "mnemonic": "JLE",         "format": "D", "category": "control",   "description": "Jump if less or equal"},
    {"hex": 0x4F, "mnemonic": "LOAD8",       "format": "C", "category": "memory",    "description": "Load 8-bit"},
    # SIMD vector ops (0x50-0x5F)
    {"hex": 0x50, "mnemonic": "VLOAD",       "format": "G", "category": "vector",    "description": "Vector load"},
    {"hex": 0x51, "mnemonic": "VSTORE",      "format": "G", "category": "vector",    "description": "Vector store"},
    {"hex": 0x52, "mnemonic": "VADD",        "format": "E", "category": "vector",    "description": "Vector add"},
    {"hex": 0x53, "mnemonic": "VSUB",        "format": "E", "category": "vector",    "description": "Vector subtract"},
    {"hex": 0x54, "mnemonic": "VMUL",        "format": "E", "category": "vector",    "description": "Vector multiply"},
    {"hex": 0x55, "mnemonic": "VDIV",        "format": "E", "category": "vector",    "description": "Vector divide"},
    {"hex": 0x56, "mnemonic": "VFMA",        "format": "E", "category": "vector",    "description": "Fused multiply-add"},
    {"hex": 0x57, "mnemonic": "STORE8",      "format": "C", "category": "memory",    "description": "Store 8-bit"},
    # A2A protocol (0x60-0x7B)
    {"hex": 0x60, "mnemonic": "TELL",        "format": "G", "category": "a2a",       "description": "Send message to agent"},
    {"hex": 0x61, "mnemonic": "ASK",         "format": "G", "category": "a2a",       "description": "Request from agent"},
    {"hex": 0x62, "mnemonic": "DELEGATE",    "format": "G", "category": "a2a",       "description": "Delegate task"},
    {"hex": 0x63, "mnemonic": "DELEGATE_RESULT","format":"G","category": "a2a",       "description": "Delegate result"},
    {"hex": 0x64, "mnemonic": "REPORT_STATUS","format":"G", "category": "a2a",       "description": "Report status"},
    {"hex": 0x65, "mnemonic": "REQUEST_OVERRIDE","format":"G","category":"a2a",       "description": "Request override"},
    {"hex": 0x66, "mnemonic": "BROADCAST",   "format": "G", "category": "a2a",       "description": "Broadcast to fleet"},
    {"hex": 0x67, "mnemonic": "REDUCE",      "format": "G", "category": "a2a",       "description": "Reduce across agents"},
    {"hex": 0x68, "mnemonic": "DECLARE_INTENT","format":"G","category": "a2a",        "description": "Declare intent"},
    {"hex": 0x69, "mnemonic": "ASSERT_GOAL", "format": "G", "category": "a2a",       "description": "Assert goal"},
    {"hex": 0x6A, "mnemonic": "VERIFY_OUTCOME","format":"G","category": "a2a",        "description": "Verify outcome"},
    {"hex": 0x6B, "mnemonic": "EXPLAIN_FAILURE","format":"G","category": "a2a",       "description": "Explain failure"},
    {"hex": 0x6C, "mnemonic": "SET_PRIORITY", "format": "G", "category": "a2a",      "description": "Set priority"},
    {"hex": 0x70, "mnemonic": "TRUST_CHECK",  "format": "G", "category": "a2a",      "description": "Check trust level"},
    {"hex": 0x71, "mnemonic": "TRUST_UPDATE", "format": "G", "category": "a2a",      "description": "Update trust level"},
    {"hex": 0x72, "mnemonic": "TRUST_QUERY",  "format": "G", "category": "a2a",      "description": "Query trust level"},
    {"hex": 0x73, "mnemonic": "REVOKE_TRUST", "format": "G", "category": "a2a",     "description": "Revoke trust"},
    {"hex": 0x74, "mnemonic": "CAP_REQUIRE",  "format": "G", "category": "a2a",     "description": "Require capability"},
    {"hex": 0x75, "mnemonic": "CAP_REQUEST",  "format": "G", "category": "a2a",     "description": "Request capability"},
    {"hex": 0x76, "mnemonic": "CAP_GRANT",    "format": "G", "category": "a2a",     "description": "Grant capability"},
    {"hex": 0x77, "mnemonic": "CAP_REVOKE",   "format": "G", "category": "a2a",     "description": "Revoke capability"},
    {"hex": 0x78, "mnemonic": "BARRIER",      "format": "G", "category": "a2a",     "description": "Barrier synchronization"},
    {"hex": 0x79, "mnemonic": "SYNC_CLOCK",   "format": "G", "category": "a2a",     "description": "Clock synchronization"},
    {"hex": 0x7A, "mnemonic": "FORMATION_UPDATE","format":"G","category":"a2a",      "description": "Update formation"},
    {"hex": 0x7B, "mnemonic": "EMERGENCY_STOP","format":"A","category": "a2a",       "description": "Emergency stop"},
    # System (0x80-0x84)
    {"hex": 0x80, "mnemonic": "HALT",         "format": "A", "category": "system",  "description": "Halt execution"},
    {"hex": 0x81, "mnemonic": "YIELD",        "format": "A", "category": "system",  "description": "Yield execution"},
    {"hex": 0x82, "mnemonic": "RESOURCE_ACQUIRE","format":"G","category":"system",    "description": "Acquire resource"},
    {"hex": 0x83, "mnemonic": "RESOURCE_RELEASE","format":"G","category":"system",    "description": "Release resource"},
    {"hex": 0x84, "mnemonic": "DEBUG_BREAK",  "format": "A", "category": "debug",   "description": "Debug breakpoint"},
]

# Mark all oracle1 opcodes with their source
for _op in ORACLE1_OPCODES:
    _op["source"] = "oracle1"
    _op.setdefault("confidence", False)


# ── Source: jc1 (C VM — formats.py, ~67 opcodes) ──────────────────────────────

JC1_OPCODES: List[dict] = [
    {"hex": 0x00, "mnemonic": "HALT",       "format": "A", "category": "system",      "description": "Stop execution"},
    {"hex": 0x01, "mnemonic": "NOP",        "format": "A", "category": "system",      "description": "No operation"},
    {"hex": 0x02, "mnemonic": "RET",        "format": "A", "category": "system",      "description": "Return from subroutine"},
    {"hex": 0x03, "mnemonic": "IRET",       "format": "A", "category": "system",      "description": "Return from interrupt"},
    {"hex": 0x08, "mnemonic": "INC",        "format": "B", "category": "arithmetic",  "description": "rd = rd + 1"},
    {"hex": 0x09, "mnemonic": "DEC",        "format": "B", "category": "arithmetic",  "description": "rd = rd - 1"},
    {"hex": 0x0A, "mnemonic": "NOT",        "format": "B", "category": "logic",       "description": "rd = ~rd"},
    {"hex": 0x0B, "mnemonic": "NEG",        "format": "B", "category": "arithmetic",  "description": "rd = -rd"},
    {"hex": 0x0C, "mnemonic": "PUSH",       "format": "B", "category": "stack",       "description": "Push rd"},
    {"hex": 0x0D, "mnemonic": "POP",        "format": "B", "category": "stack",       "description": "Pop rd"},
    {"hex": 0x0E, "mnemonic": "CONF_LOAD",  "format": "B", "category": "confidence",  "description": "Load confidence"},
    {"hex": 0x0F, "mnemonic": "CONF_STORE", "format": "B", "category": "confidence",  "description": "Store confidence"},
    {"hex": 0x10, "mnemonic": "SYS",        "format": "C", "category": "system",      "description": "System call"},
    {"hex": 0x17, "mnemonic": "STRIPCONF",  "format": "C", "category": "confidence",  "description": "Strip confidence"},
    {"hex": 0x18, "mnemonic": "MOVI",       "format": "D", "category": "move",        "description": "rd = sign_extend(imm8)"},
    {"hex": 0x19, "mnemonic": "ADDI",       "format": "D", "category": "arithmetic",  "description": "rd = rd + imm8"},
    {"hex": 0x1A, "mnemonic": "SUBI",       "format": "D", "category": "arithmetic",  "description": "rd = rd - imm8"},
    {"hex": 0x1B, "mnemonic": "ANDI",       "format": "D", "category": "logic",       "description": "rd = rd & imm8"},
    {"hex": 0x1C, "mnemonic": "ORI",        "format": "D", "category": "logic",       "description": "rd = rd | imm8"},
    {"hex": 0x1D, "mnemonic": "XORI",       "format": "D", "category": "logic",       "description": "rd = rd ^ imm8"},
    {"hex": 0x1E, "mnemonic": "SHLI",       "format": "D", "category": "shift",       "description": "rd = rd << imm8"},
    {"hex": 0x1F, "mnemonic": "SHRI",       "format": "D", "category": "shift",       "description": "rd = rd >> imm8"},
    {"hex": 0x20, "mnemonic": "ADD",        "format": "E", "category": "arithmetic",  "description": "rd = rs1 + rs2"},
    {"hex": 0x21, "mnemonic": "SUB",        "format": "E", "category": "arithmetic",  "description": "rd = rs1 - rs2"},
    {"hex": 0x22, "mnemonic": "MUL",        "format": "E", "category": "arithmetic",  "description": "rd = rs1 * rs2"},
    {"hex": 0x23, "mnemonic": "DIV",        "format": "E", "category": "arithmetic",  "description": "rd = rs1 / rs2"},
    {"hex": 0x24, "mnemonic": "MOD",        "format": "E", "category": "arithmetic",  "description": "rd = rs1 % rs2"},
    {"hex": 0x25, "mnemonic": "AND",        "format": "E", "category": "logic",       "description": "rd = rs1 & rs2"},
    {"hex": 0x26, "mnemonic": "OR",         "format": "E", "category": "logic",       "description": "rd = rs1 | rs2"},
    {"hex": 0x27, "mnemonic": "XOR",        "format": "E", "category": "logic",       "description": "rd = rs1 ^ rs2"},
    {"hex": 0x28, "mnemonic": "SHL",        "format": "E", "category": "shift",       "description": "rd = rs1 << rs2"},
    {"hex": 0x29, "mnemonic": "SHR",        "format": "E", "category": "shift",       "description": "rd = rs1 >> rs2"},
    {"hex": 0x2A, "mnemonic": "MIN",        "format": "E", "category": "arithmetic",  "description": "rd = min(rs1, rs2)"},
    {"hex": 0x2B, "mnemonic": "MAX",        "format": "E", "category": "arithmetic",  "description": "rd = max(rs1, rs2)"},
    {"hex": 0x2C, "mnemonic": "CMP_EQ",     "format": "E", "category": "compare",     "description": "rd = (rs1 == rs2) ? 1 : 0"},
    {"hex": 0x2D, "mnemonic": "CMP_LT",     "format": "E", "category": "compare",     "description": "rd = (rs1 < rs2) ? 1 : 0"},
    {"hex": 0x2E, "mnemonic": "CMP_GT",     "format": "E", "category": "compare",     "description": "rd = (rs1 > rs2) ? 1 : 0"},
    {"hex": 0x2F, "mnemonic": "CMP_NE",     "format": "E", "category": "compare",     "description": "rd = (rs1 != rs2) ? 1 : 0"},
    {"hex": 0x30, "mnemonic": "FADD",       "format": "E", "category": "float",       "description": "Float add"},
    {"hex": 0x31, "mnemonic": "FSUB",       "format": "E", "category": "float",       "description": "Float subtract"},
    {"hex": 0x32, "mnemonic": "FMUL",       "format": "E", "category": "float",       "description": "Float multiply"},
    {"hex": 0x33, "mnemonic": "FDIV",       "format": "E", "category": "float",       "description": "Float divide"},
    {"hex": 0x34, "mnemonic": "FMIN",       "format": "E", "category": "float",       "description": "Float min"},
    {"hex": 0x35, "mnemonic": "FMAX",       "format": "E", "category": "float",       "description": "Float max"},
    {"hex": 0x36, "mnemonic": "FTOI",       "format": "E", "category": "convert",     "description": "Float to integer"},
    {"hex": 0x37, "mnemonic": "ITOF",       "format": "E", "category": "convert",     "description": "Integer to float"},
    {"hex": 0x38, "mnemonic": "LOAD",       "format": "E", "category": "memory",      "description": "Load from memory"},
    {"hex": 0x39, "mnemonic": "STORE",      "format": "E", "category": "memory",      "description": "Store to memory"},
    {"hex": 0x3A, "mnemonic": "MOV",        "format": "E", "category": "move",        "description": "rd = rs1"},
    {"hex": 0x3B, "mnemonic": "SWP",        "format": "E", "category": "move",        "description": "Swap(rd, rs1)"},
    {"hex": 0x3C, "mnemonic": "JZ",         "format": "E", "category": "control",     "description": "Jump if zero"},
    {"hex": 0x3D, "mnemonic": "JNZ",        "format": "E", "category": "control",     "description": "Jump if not zero"},
    {"hex": 0x3E, "mnemonic": "JLT",        "format": "E", "category": "control",     "description": "Jump if less than zero"},
    {"hex": 0x3F, "mnemonic": "JGT",        "format": "E", "category": "control",     "description": "Jump if greater than zero"},
    {"hex": 0x40, "mnemonic": "MOVI16",     "format": "F", "category": "move",        "description": "rd = imm16"},
    {"hex": 0x41, "mnemonic": "ADDI16",     "format": "F", "category": "arithmetic",  "description": "rd = rd + imm16"},
    {"hex": 0x42, "mnemonic": "SUBI16",     "format": "F", "category": "arithmetic",  "description": "rd = rd - imm16"},
    {"hex": 0x43, "mnemonic": "JMP",        "format": "F", "category": "control",     "description": "pc += imm16"},
    {"hex": 0x44, "mnemonic": "JAL",        "format": "F", "category": "control",     "description": "Jump and link"},
    {"hex": 0x48, "mnemonic": "LOADOFF",    "format": "G", "category": "memory",      "description": "rd = mem[rs1 + imm16]"},
    {"hex": 0x49, "mnemonic": "STOREOFF",   "format": "G", "category": "memory",      "description": "mem[rs1 + imm16] = rd"},
    {"hex": 0x4A, "mnemonic": "LOADI",      "format": "G", "category": "memory",      "description": "Load indirect"},
    {"hex": 0x60, "mnemonic": "CONF_ADD",   "format": "E", "category": "confidence",  "description": "Conf add", "confidence": True},
    {"hex": 0x61, "mnemonic": "CONF_SUB",   "format": "E", "category": "confidence",  "description": "Conf sub", "confidence": True},
    {"hex": 0x62, "mnemonic": "CONF_MUL",   "format": "E", "category": "confidence",  "description": "Conf mul", "confidence": True},
    {"hex": 0x63, "mnemonic": "CONF_DIV",   "format": "E", "category": "confidence",  "description": "Conf div", "confidence": True},
    {"hex": 0x64, "mnemonic": "CONF_FADD",  "format": "E", "category": "confidence",  "description": "Conf float add", "confidence": True},
    {"hex": 0x65, "mnemonic": "CONF_FSUB",  "format": "E", "category": "confidence",  "description": "Conf float sub", "confidence": True},
    {"hex": 0x66, "mnemonic": "CONF_FMUL",  "format": "E", "category": "confidence",  "description": "Conf float mul", "confidence": True},
    {"hex": 0x67, "mnemonic": "CONF_FDIV",  "format": "E", "category": "confidence",  "description": "Conf float div", "confidence": True},
    {"hex": 0x68, "mnemonic": "CONF_MERGE", "format": "E", "category": "confidence",  "description": "Conf merge", "confidence": True},
    {"hex": 0x69, "mnemonic": "CONF_THRESHOLD","format":"E","category": "confidence",  "description": "Conf threshold", "confidence": True},
]

for _op in JC1_OPCODES:
    _op["source"] = "jc1"
    _op.setdefault("confidence", False)


# ── Source: babel (Multilingual — 120 opcodes including 16 viewpoint) ──────────

BABEL_OPCODES: List[dict] = [
    # Core arithmetic (same as converged 0x00-0x2F)
    {"hex": 0x00, "mnemonic": "HALT",    "format": "A", "category": "system",      "description": "Stop execution"},
    {"hex": 0x01, "mnemonic": "NOP",     "format": "A", "category": "system",      "description": "No operation"},
    {"hex": 0x02, "mnemonic": "RET",     "format": "A", "category": "system",      "description": "Return"},
    {"hex": 0x04, "mnemonic": "BRK",     "format": "A", "category": "debug",       "description": "Breakpoint"},
    {"hex": 0x08, "mnemonic": "INC",     "format": "B", "category": "arithmetic",  "description": "Increment"},
    {"hex": 0x09, "mnemonic": "DEC",     "format": "B", "category": "arithmetic",  "description": "Decrement"},
    {"hex": 0x0A, "mnemonic": "NOT",     "format": "B", "category": "logic",       "description": "Bitwise NOT"},
    {"hex": 0x0B, "mnemonic": "NEG",     "format": "B", "category": "arithmetic",  "description": "Negate"},
    {"hex": 0x0C, "mnemonic": "PUSH",    "format": "B", "category": "stack",       "description": "Push"},
    {"hex": 0x0D, "mnemonic": "POP",     "format": "B", "category": "stack",       "description": "Pop"},
    {"hex": 0x0E, "mnemonic": "CONF_LD", "format": "B", "category": "confidence",  "description": "Load confidence"},
    {"hex": 0x0F, "mnemonic": "CONF_ST", "format": "B", "category": "confidence",  "description": "Store confidence"},
    {"hex": 0x10, "mnemonic": "SYS",     "format": "C", "category": "system",      "description": "System call"},
    {"hex": 0x12, "mnemonic": "DBG",     "format": "C", "category": "debug",       "description": "Debug print"},
    {"hex": 0x18, "mnemonic": "MOVI",    "format": "D", "category": "move",        "description": "Move immediate"},
    {"hex": 0x19, "mnemonic": "ADDI",    "format": "D", "category": "arithmetic",  "description": "Add immediate"},
    {"hex": 0x1A, "mnemonic": "SUBI",    "format": "D", "category": "arithmetic",  "description": "Sub immediate"},
    {"hex": 0x1B, "mnemonic": "ANDI",    "format": "D", "category": "logic",       "description": "AND immediate"},
    {"hex": 0x1C, "mnemonic": "ORI",     "format": "D", "category": "logic",       "description": "OR immediate"},
    {"hex": 0x1D, "mnemonic": "XORI",    "format": "D", "category": "logic",       "description": "XOR immediate"},
    {"hex": 0x1E, "mnemonic": "SHLI",    "format": "D", "category": "shift",       "description": "Shift left imm"},
    {"hex": 0x1F, "mnemonic": "SHRI",    "format": "D", "category": "shift",       "description": "Shift right imm"},
    {"hex": 0x20, "mnemonic": "ADD",     "format": "E", "category": "arithmetic",  "description": "Add"},
    {"hex": 0x21, "mnemonic": "SUB",     "format": "E", "category": "arithmetic",  "description": "Subtract"},
    {"hex": 0x22, "mnemonic": "MUL",     "format": "E", "category": "arithmetic",  "description": "Multiply"},
    {"hex": 0x23, "mnemonic": "DIV",     "format": "E", "category": "arithmetic",  "description": "Divide"},
    {"hex": 0x24, "mnemonic": "MOD",     "format": "E", "category": "arithmetic",  "description": "Modulo"},
    {"hex": 0x25, "mnemonic": "AND",     "format": "E", "category": "logic",       "description": "AND"},
    {"hex": 0x26, "mnemonic": "OR",      "format": "E", "category": "logic",       "description": "OR"},
    {"hex": 0x27, "mnemonic": "XOR",     "format": "E", "category": "logic",       "description": "XOR"},
    {"hex": 0x28, "mnemonic": "SHL",     "format": "E", "category": "shift",       "description": "Shift left"},
    {"hex": 0x29, "mnemonic": "SHR",     "format": "E", "category": "shift",       "description": "Shift right"},
    {"hex": 0x2A, "mnemonic": "MIN",     "format": "E", "category": "arithmetic",  "description": "Min"},
    {"hex": 0x2B, "mnemonic": "MAX",     "format": "E", "category": "arithmetic",  "description": "Max"},
    {"hex": 0x2C, "mnemonic": "CMP_EQ",  "format": "E", "category": "compare",     "description": "Compare equal"},
    {"hex": 0x2D, "mnemonic": "CMP_LT",  "format": "E", "category": "compare",     "description": "Compare less"},
    {"hex": 0x2E, "mnemonic": "CMP_GT",  "format": "E", "category": "compare",     "description": "Compare greater"},
    {"hex": 0x2F, "mnemonic": "CMP_NE",  "format": "E", "category": "compare",     "description": "Compare not equal"},
    # Float (0x30-0x37)
    {"hex": 0x30, "mnemonic": "FADD",    "format": "E", "category": "float",       "description": "Float add"},
    {"hex": 0x31, "mnemonic": "FSUB",    "format": "E", "category": "float",       "description": "Float sub"},
    {"hex": 0x32, "mnemonic": "FMUL",    "format": "E", "category": "float",       "description": "Float mul"},
    {"hex": 0x33, "mnemonic": "FDIV",    "format": "E", "category": "float",       "description": "Float div"},
    {"hex": 0x34, "mnemonic": "FMIN",    "format": "E", "category": "float",       "description": "Float min"},
    {"hex": 0x35, "mnemonic": "FMAX",    "format": "E", "category": "float",       "description": "Float max"},
    {"hex": 0x36, "mnemonic": "FTOI",    "format": "E", "category": "convert",     "description": "Float to int"},
    {"hex": 0x37, "mnemonic": "ITOF",    "format": "E", "category": "convert",     "description": "Int to float"},
    # Memory (0x38-0x3B)
    {"hex": 0x38, "mnemonic": "LOAD",    "format": "E", "category": "memory",      "description": "Load"},
    {"hex": 0x39, "mnemonic": "STORE",   "format": "E", "category": "memory",      "description": "Store"},
    {"hex": 0x3A, "mnemonic": "MOV",     "format": "E", "category": "move",        "description": "Move"},
    {"hex": 0x3B, "mnemonic": "SWP",     "format": "E", "category": "move",        "description": "Swap"},
    # Control (0x3C-0x44)
    {"hex": 0x3C, "mnemonic": "JZ",      "format": "E", "category": "control",     "description": "Jump if zero"},
    {"hex": 0x3D, "mnemonic": "JNZ",     "format": "E", "category": "control",     "description": "Jump if not zero"},
    {"hex": 0x3E, "mnemonic": "JLT",     "format": "E", "category": "control",     "description": "Jump if less"},
    {"hex": 0x3F, "mnemonic": "JGT",     "format": "E", "category": "control",     "description": "Jump if greater"},
    {"hex": 0x40, "mnemonic": "MOVI16",  "format": "F", "category": "move",        "description": "Move imm16"},
    {"hex": 0x43, "mnemonic": "JMP",     "format": "F", "category": "control",     "description": "Jump"},
    {"hex": 0x44, "mnemonic": "JAL",     "format": "F", "category": "control",     "description": "Jump and link"},
    # A2A (0x50-0x5F)
    {"hex": 0x50, "mnemonic": "TELL",    "format": "E", "category": "a2a",         "description": "Tell agent"},
    {"hex": 0x51, "mnemonic": "ASK",     "format": "E", "category": "a2a",         "description": "Ask agent"},
    {"hex": 0x52, "mnemonic": "DELEG",   "format": "E", "category": "a2a",         "description": "Delegate"},
    {"hex": 0x53, "mnemonic": "BCAST",   "format": "E", "category": "a2a",         "description": "Broadcast"},
    {"hex": 0x54, "mnemonic": "ACCEPT",  "format": "E", "category": "a2a",         "description": "Accept"},
    {"hex": 0x55, "mnemonic": "DECLINE", "format": "E", "category": "a2a",         "description": "Decline"},
    {"hex": 0x56, "mnemonic": "REPORT",  "format": "E", "category": "a2a",         "description": "Report"},
    {"hex": 0x57, "mnemonic": "MERGE",   "format": "E", "category": "a2a",         "description": "Merge"},
    {"hex": 0x58, "mnemonic": "FORK",    "format": "E", "category": "a2a",         "description": "Fork agent"},
    {"hex": 0x59, "mnemonic": "JOIN",    "format": "E", "category": "a2a",         "description": "Join agent"},
    {"hex": 0x5A, "mnemonic": "SIGNAL",  "format": "E", "category": "a2a",         "description": "Signal"},
    {"hex": 0x5B, "mnemonic": "AWAIT",   "format": "E", "category": "a2a",         "description": "Await"},
    {"hex": 0x5C, "mnemonic": "TRUST",   "format": "E", "category": "a2a",         "description": "Set trust"},
    {"hex": 0x5E, "mnemonic": "STATUS",  "format": "E", "category": "a2a",         "description": "Query status"},
    {"hex": 0x5F, "mnemonic": "HEARTBT", "format": "E", "category": "a2a",         "description": "Heartbeat"},
    # Confidence (0x60-0x6F subset)
    {"hex": 0x60, "mnemonic": "C_ADD",   "format": "E", "category": "confidence",  "description": "Conf add", "confidence": True},
    {"hex": 0x61, "mnemonic": "C_SUB",   "format": "E", "category": "confidence",  "description": "Conf sub", "confidence": True},
    {"hex": 0x62, "mnemonic": "C_MUL",   "format": "E", "category": "confidence",  "description": "Conf mul", "confidence": True},
    {"hex": 0x63, "mnemonic": "C_DIV",   "format": "E", "category": "confidence",  "description": "Conf div", "confidence": True},
    {"hex": 0x68, "mnemonic": "C_MERGE", "format": "E", "category": "confidence",  "description": "Conf merge", "confidence": True},
    {"hex": 0x69, "mnemonic": "C_THRESH","format": "D", "category": "confidence",  "description": "Conf threshold", "confidence": True},
    {"hex": 0x6D, "mnemonic": "C_CALIB", "format": "E", "category": "confidence",  "description": "Calibrate", "confidence": True},
    {"hex": 0x6F, "mnemonic": "C_VOTE",  "format": "E", "category": "confidence",  "description": "Weighted vote", "confidence": True},
    # 16 Viewpoint ops (0x70-0x7F) — Babel exclusive
    {"hex": 0x70, "mnemonic": "V_EVID",  "format": "E", "category": "viewpoint",   "description": "Evidentiality"},
    {"hex": 0x71, "mnemonic": "V_EPIST", "format": "E", "category": "viewpoint",   "description": "Epistemic stance"},
    {"hex": 0x72, "mnemonic": "V_MIR",   "format": "E", "category": "viewpoint",   "description": "Mirative"},
    {"hex": 0x73, "mnemonic": "V_NEG",   "format": "E", "category": "viewpoint",   "description": "Negation scope"},
    {"hex": 0x74, "mnemonic": "V_TENSE", "format": "E", "category": "viewpoint",   "description": "Temporal viewpoint"},
    {"hex": 0x75, "mnemonic": "V_ASPEC", "format": "E", "category": "viewpoint",   "description": "Aspectual viewpoint"},
    {"hex": 0x76, "mnemonic": "V_MODAL", "format": "E", "category": "viewpoint",   "description": "Modal force"},
    {"hex": 0x77, "mnemonic": "V_POLIT", "format": "E", "category": "viewpoint",   "description": "Politeness register"},
    {"hex": 0x78, "mnemonic": "V_HONOR", "format": "E", "category": "viewpoint",   "description": "Honorific level"},
    {"hex": 0x79, "mnemonic": "V_TOPIC", "format": "E", "category": "viewpoint",   "description": "Topic-comment"},
    {"hex": 0x7A, "mnemonic": "V_FOCUS", "format": "E", "category": "viewpoint",   "description": "Information focus"},
    {"hex": 0x7B, "mnemonic": "V_CASE",  "format": "E", "category": "viewpoint",   "description": "Case scope"},
    {"hex": 0x7C, "mnemonic": "V_AGREE", "format": "E", "category": "viewpoint",   "description": "Agreement"},
    {"hex": 0x7D, "mnemonic": "V_CLASS", "format": "E", "category": "viewpoint",   "description": "Classifier"},
    {"hex": 0x7E, "mnemonic": "V_INFL",  "format": "E", "category": "viewpoint",   "description": "Inflection"},
    {"hex": 0x7F, "mnemonic": "V_PRAGMA","format": "E", "category": "viewpoint",   "description": "Pragmatic context"},
    # Crypto/extended math (subset from converged)
    {"hex": 0x90, "mnemonic": "ABS",     "format": "E", "category": "math",        "description": "Absolute value"},
    {"hex": 0x91, "mnemonic": "SIGN",    "format": "E", "category": "math",        "description": "Sign"},
    {"hex": 0x99, "mnemonic": "SHA256",  "format": "E", "category": "crypto",      "description": "SHA-256"},
    {"hex": 0x9A, "mnemonic": "RND",     "format": "E", "category": "math",        "description": "Random"},
    {"hex": 0x9B, "mnemonic": "SEED",    "format": "E", "category": "math",        "description": "Seed PRNG"},
    {"hex": 0xAA, "mnemonic": "HASH",    "format": "E", "category": "crypto",      "description": "Hash"},
    {"hex": 0xAB, "mnemonic": "HMAC",    "format": "E", "category": "crypto",      "description": "HMAC"},
    {"hex": 0xAC, "mnemonic": "VERIFY",  "format": "E", "category": "crypto",      "description": "Verify signature"},
    {"hex": 0xAD, "mnemonic": "ENCRYPT", "format": "E", "category": "crypto",      "description": "Encrypt"},
    {"hex": 0xAE, "mnemonic": "DECRYPT", "format": "E", "category": "crypto",      "description": "Decrypt"},
    {"hex": 0xAF, "mnemonic": "KEYGEN",  "format": "E", "category": "crypto",      "description": "Generate keypair"},
    # Tensor/ML subset
    {"hex": 0xC3, "mnemonic": "TRELU",   "format": "E", "category": "tensor",      "description": "ReLU"},
    {"hex": 0xC4, "mnemonic": "TSIGM",   "format": "E", "category": "tensor",      "description": "Sigmoid"},
    {"hex": 0xCD, "mnemonic": "TTOKEN",  "format": "E", "category": "tensor",      "description": "Tokenize"},
    {"hex": 0xCE, "mnemonic": "TDETOK",  "format": "E", "category": "tensor",      "description": "Detokenize"},
    # System
    {"hex": 0xF0, "mnemonic": "HALT_ERR","format": "A", "category": "system",      "description": "Halt with error"},
    {"hex": 0xF2, "mnemonic": "DUMP",    "format": "A", "category": "debug",       "description": "Dump registers"},
    {"hex": 0xF3, "mnemonic": "ASSERT",  "format": "A", "category": "debug",       "description": "Assert"},
    {"hex": 0xF5, "mnemonic": "VER",     "format": "A", "category": "system",      "description": "ISA version"},
    {"hex": 0xFF, "mnemonic": "ILLEGAL", "format": "A", "category": "system",      "description": "Illegal instruction"},
]

for _op in BABEL_OPCODES:
    _op["source"] = "babel"
    _op.setdefault("confidence", False)


# ── Source: converged (isa_unified.py — 247 opcodes) ──────────────────────────

def _build_converged() -> List[dict]:
    """Build the full converged ISA from isa_unified.py data."""
    ops = []
    def op(code, mnem, fmt, cat, src, conf=False, res=False):
        ops.append({
            "hex": code, "mnemonic": mnem, "format": fmt,
            "category": cat, "description": "", "source": src,
            "confidence": conf, "reserved": res,
        })

    # 0x00-0x03: System Control
    op(0x00, "HALT",   "A", "system",      "converged")
    op(0x01, "NOP",    "A", "system",      "converged")
    op(0x02, "RET",    "A", "system",      "oracle1")
    op(0x03, "IRET",   "A", "system",      "jetsonclaw1")
    # 0x04-0x07: Interrupt/Debug
    op(0x04, "BRK",    "A", "debug",       "converged")
    op(0x05, "WFI",    "A", "system",      "jetsonclaw1")
    op(0x06, "RESET",  "A", "system",      "jetsonclaw1")
    op(0x07, "SYN",    "A", "system",      "jetsonclaw1")
    # 0x08-0x0F: Single Register
    op(0x08, "INC",    "B", "arithmetic",  "converged")
    op(0x09, "DEC",    "B", "arithmetic",  "converged")
    op(0x0A, "NOT",    "B", "logic",       "converged")
    op(0x0B, "NEG",    "B", "arithmetic",  "converged")
    op(0x0C, "PUSH",   "B", "stack",       "converged")
    op(0x0D, "POP",    "B", "stack",       "converged")
    op(0x0E, "CONF_LD","B", "confidence",  "converged")
    op(0x0F, "CONF_ST","B", "confidence",  "converged")
    # 0x10-0x17: Immediate Only
    op(0x10, "SYS",    "C", "system",      "converged")
    op(0x11, "TRAP",   "C", "system",      "jetsonclaw1")
    op(0x12, "DBG",    "C", "debug",       "converged")
    op(0x13, "CLF",    "C", "system",      "oracle1")
    op(0x14, "SEMA",   "C", "concurrency", "jetsonclaw1")
    op(0x15, "YIELD",  "C", "concurrency", "converged")
    op(0x16, "CACHE",  "C", "system",      "jetsonclaw1")
    op(0x17, "STRIPCF","C", "confidence",  "jetsonclaw1")
    # 0x18-0x1F: Register + Imm8
    op(0x18, "MOVI",   "D", "move",        "converged")
    op(0x19, "ADDI",   "D", "arithmetic",  "converged")
    op(0x1A, "SUBI",   "D", "arithmetic",  "converged")
    op(0x1B, "ANDI",   "D", "logic",       "converged")
    op(0x1C, "ORI",    "D", "logic",       "converged")
    op(0x1D, "XORI",   "D", "logic",       "converged")
    op(0x1E, "SHLI",   "D", "shift",       "converged")
    op(0x1F, "SHRI",   "D", "shift",       "converged")
    # 0x20-0x2F: Integer Arithmetic
    op(0x20, "ADD",    "E", "arithmetic",  "converged")
    op(0x21, "SUB",    "E", "arithmetic",  "converged")
    op(0x22, "MUL",    "E", "arithmetic",  "converged")
    op(0x23, "DIV",    "E", "arithmetic",  "converged")
    op(0x24, "MOD",    "E", "arithmetic",  "converged")
    op(0x25, "AND",    "E", "logic",       "converged")
    op(0x26, "OR",     "E", "logic",       "converged")
    op(0x27, "XOR",    "E", "logic",       "converged")
    op(0x28, "SHL",    "E", "shift",       "converged")
    op(0x29, "SHR",    "E", "shift",       "converged")
    op(0x2A, "MIN",    "E", "arithmetic",  "converged")
    op(0x2B, "MAX",    "E", "arithmetic",  "converged")
    op(0x2C, "CMP_EQ", "E", "compare",     "converged")
    op(0x2D, "CMP_LT", "E", "compare",     "converged")
    op(0x2E, "CMP_GT", "E", "compare",     "converged")
    op(0x2F, "CMP_NE", "E", "compare",     "converged")
    # 0x30-0x3F: Float, Memory, Control
    op(0x30, "FADD",   "E", "float",       "oracle1")
    op(0x31, "FSUB",   "E", "float",       "oracle1")
    op(0x32, "FMUL",   "E", "float",       "oracle1")
    op(0x33, "FDIV",   "E", "float",       "oracle1")
    op(0x34, "FMIN",   "E", "float",       "oracle1")
    op(0x35, "FMAX",   "E", "float",       "oracle1")
    op(0x36, "FTOI",   "E", "convert",     "oracle1")
    op(0x37, "ITOF",   "E", "convert",     "oracle1")
    op(0x38, "LOAD",   "E", "memory",      "converged")
    op(0x39, "STORE",  "E", "memory",      "converged")
    op(0x3A, "MOV",    "E", "move",        "converged")
    op(0x3B, "SWP",    "E", "move",        "converged")
    op(0x3C, "JZ",     "E", "control",     "converged")
    op(0x3D, "JNZ",    "E", "control",     "converged")
    op(0x3E, "JLT",    "E", "control",     "converged")
    op(0x3F, "JGT",    "E", "control",     "converged")
    # 0x40-0x47: Register + Imm16
    op(0x40, "MOVI16", "F", "move",        "converged")
    op(0x41, "ADDI16", "F", "arithmetic",  "converged")
    op(0x42, "SUBI16", "F", "arithmetic",  "converged")
    op(0x43, "JMP",    "F", "control",     "converged")
    op(0x44, "JAL",    "F", "control",     "converged")
    op(0x45, "CALL",   "F", "control",     "jetsonclaw1")
    op(0x46, "LOOP",   "F", "control",     "jetsonclaw1")
    op(0x47, "SELECT", "F", "control",     "oracle1")
    # 0x48-0x4F: Register + Register + Imm16
    op(0x48, "LOADOFF","G", "memory",      "converged")
    op(0x49, "STOREOF","G", "memory",      "converged")
    op(0x4A, "LOADI",  "G", "memory",      "jetsonclaw1")
    op(0x4B, "STOREI", "G", "memory",      "jetsonclaw1")
    op(0x4C, "ENTER",  "G", "stack",       "jetsonclaw1")
    op(0x4D, "LEAVE",  "G", "stack",       "jetsonclaw1")
    op(0x4E, "COPY",   "G", "memory",      "jetsonclaw1")
    op(0x4F, "FILL",   "G", "memory",      "jetsonclaw1")
    # 0x50-0x5F: Agent-to-Agent
    op(0x50, "TELL",   "E", "a2a",         "converged")
    op(0x51, "ASK",    "E", "a2a",         "converged")
    op(0x52, "DELEG",  "E", "a2a",         "converged")
    op(0x53, "BCAST",  "E", "a2a",         "converged")
    op(0x54, "ACCEPT", "E", "a2a",         "converged")
    op(0x55, "DECLINE","E", "a2a",         "converged")
    op(0x56, "REPORT", "E", "a2a",         "converged")
    op(0x57, "MERGE",  "E", "a2a",         "converged")
    op(0x58, "FORK",   "E", "a2a",         "converged")
    op(0x59, "JOIN",   "E", "a2a",         "converged")
    op(0x5A, "SIGNAL", "E", "a2a",         "converged")
    op(0x5B, "AWAIT",  "E", "a2a",         "converged")
    op(0x5C, "TRUST",  "E", "a2a",         "converged")
    op(0x5D, "DISCOV", "E", "a2a",         "oracle1")
    op(0x5E, "STATUS", "E", "a2a",         "converged")
    op(0x5F, "HEARTBT","E", "a2a",         "converged")
    # 0x60-0x6F: Confidence
    op(0x60, "C_ADD",  "E", "confidence",  "converged", conf=True)
    op(0x61, "C_SUB",  "E", "confidence",  "converged", conf=True)
    op(0x62, "C_MUL",  "E", "confidence",  "converged", conf=True)
    op(0x63, "C_DIV",  "E", "confidence",  "converged", conf=True)
    op(0x64, "C_FADD", "E", "confidence",  "oracle1",   conf=True)
    op(0x65, "C_FSUB", "E", "confidence",  "oracle1",   conf=True)
    op(0x66, "C_FMUL", "E", "confidence",  "oracle1",   conf=True)
    op(0x67, "C_FDIV", "E", "confidence",  "oracle1",   conf=True)
    op(0x68, "C_MERGE","E", "confidence",  "converged", conf=True)
    op(0x69, "C_THRESH","D","confidence",  "converged", conf=True)
    op(0x6A, "C_BOOST","E", "confidence",  "jetsonclaw1", conf=True)
    op(0x6B, "C_DECAY","E", "confidence",  "jetsonclaw1", conf=True)
    op(0x6C, "C_SOURCE","E","confidence",  "jetsonclaw1", conf=True)
    op(0x6D, "C_CALIB","E", "confidence",  "converged", conf=True)
    op(0x6E, "C_EXPLY","E", "confidence",  "oracle1",   conf=True)
    op(0x6F, "C_VOTE", "E", "confidence",  "converged", conf=True)
    # 0x70-0x7F: Viewpoint (Babel)
    for i, mn in enumerate([
        "V_EVID","V_EPIST","V_MIR","V_NEG","V_TENSE","V_ASPEC","V_MODAL","V_POLIT",
        "V_HONOR","V_TOPIC","V_FOCUS","V_CASE","V_AGREE","V_CLASS","V_INFL","V_PRAGMA"
    ]):
        op(0x70 + i, mn, "E", "viewpoint", "babel")
    # 0x80-0x8F: Sensor (JetsonClaw1)
    for i, mn in enumerate([
        "SENSE","ACTUATE","SAMPLE","ENERGY","TEMP","GPS","ACCEL","DEPTH",
        "CAMCAP","CAMDET","PWM","GPIO","I2C","SPI","UART","CANBUS"
    ]):
        op(0x80 + i, mn, "E", "sensor", "jetsonclaw1")
    # 0x90-0x9F: Extended Math/Crypto
    op(0x90, "ABS",    "E", "math",        "converged")
    op(0x91, "SIGN",   "E", "math",        "converged")
    op(0x92, "SQRT",   "E", "math",        "oracle1")
    op(0x93, "POW",    "E", "math",        "oracle1")
    op(0x94, "LOG2",   "E", "math",        "oracle1")
    op(0x95, "CLZ",    "E", "math",        "jetsonclaw1")
    op(0x96, "CTZ",    "E", "math",        "jetsonclaw1")
    op(0x97, "POPCNT", "E", "math",        "jetsonclaw1")
    op(0x98, "CRC32",  "E", "crypto",      "jetsonclaw1")
    op(0x99, "SHA256", "E", "crypto",      "converged")
    op(0x9A, "RND",    "E", "math",        "converged")
    op(0x9B, "SEED",   "E", "math",        "converged")
    op(0x9C, "FMOD",   "E", "float",       "oracle1")
    op(0x9D, "FSQRT",  "E", "float",       "oracle1")
    op(0x9E, "FSIN",   "E", "float",       "oracle1")
    op(0x9F, "FCOS",   "E", "float",       "oracle1")
    # 0xA0-0xAF: String/Collection/Crypto
    op(0xA0, "LEN",    "D", "collection",  "oracle1")
    op(0xA1, "CONCAT", "E", "collection",  "oracle1")
    op(0xA2, "AT",     "E", "collection",  "oracle1")
    op(0xA3, "SETAT",  "E", "collection",  "oracle1")
    op(0xA4, "SLICE",  "G", "collection",  "oracle1")
    op(0xA5, "REDUCE", "E", "collection",  "oracle1")
    op(0xA6, "MAP",    "E", "collection",  "oracle1")
    op(0xA7, "FILTER", "E", "collection",  "oracle1")
    op(0xA8, "SORT",   "E", "collection",  "oracle1")
    op(0xA9, "FIND",   "E", "collection",  "oracle1")
    op(0xAA, "HASH",   "E", "crypto",      "converged")
    op(0xAB, "HMAC",   "E", "crypto",      "converged")
    op(0xAC, "VERIFY", "E", "crypto",      "converged")
    op(0xAD, "ENCRYPT","E", "crypto",      "converged")
    op(0xAE, "DECRYPT","E", "crypto",      "converged")
    op(0xAF, "KEYGEN", "E", "crypto",      "converged")
    # 0xB0-0xBF: Vector/SIMD
    for i, mn in enumerate([
        "VLOAD","VSTORE","VADD","VMUL","VDOT","VNORM","VSCALE","VMAXP",
        "VMINP","VREDUCE","VGATHER","VSCATTER","VSHUF","VMERGE","VCONF","VSELECT"
    ]):
        op(0xB0 + i, mn, "E", "vector", "jetsonclaw1")
    # 0xC0-0xCF: Tensor/Neural
    for i, mn in enumerate([
        "TMATMUL","TCONV","TPOOL","TRELU","TSIGM","TSOFT","TLOSS","TGRAD",
        "TUPDATE","TADAM","TEMBED","TATTN","TSAMPLE","TTOKEN","TDETOK","TQUANT"
    ]):
        src = "oracle1" if mn in ("TTOKEN", "TDETOK") else "jetsonclaw1"
        op(0xC0 + i, mn, "E", "tensor", src)
    # 0xD0-0xDF: Extended Memory/Mapped I/O
    op(0xD0, "DMA_CPY","G", "memory",  "jetsonclaw1")
    op(0xD1, "DMA_SET","G", "memory",  "jetsonclaw1")
    op(0xD2, "MMIO_R", "G", "memory",  "jetsonclaw1")
    op(0xD3, "MMIO_W", "G", "memory",  "jetsonclaw1")
    op(0xD4, "ATOMIC", "G", "memory",  "jetsonclaw1")
    op(0xD5, "CAS",    "G", "memory",  "jetsonclaw1")
    op(0xD6, "FENCE",  "G", "memory",  "jetsonclaw1")
    op(0xD7, "MALLOC", "G", "memory",  "oracle1")
    op(0xD8, "FREE",   "G", "memory",  "oracle1")
    op(0xD9, "MPROT",  "G", "memory",  "jetsonclaw1")
    op(0xDA, "MCACHE", "G", "memory",  "jetsonclaw1")
    op(0xDB, "GPU_LD", "G", "memory",  "jetsonclaw1")
    op(0xDC, "GPU_ST", "G", "memory",  "jetsonclaw1")
    op(0xDD, "GPU_EX", "G", "compute","jetsonclaw1")
    op(0xDE, "GPU_SYNC","G","compute","jetsonclaw1")
    op(0xDF, "RESERVED_DF","G","reserved","none", res=True)
    # 0xE0-0xEF: Long Jumps/Calls
    op(0xE0, "JMPL",   "F", "control",  "converged")
    op(0xE1, "JALL",   "F", "control",  "converged")
    op(0xE2, "CALLL",  "F", "control",  "converged")
    op(0xE3, "TAIL",   "F", "control",  "oracle1")
    op(0xE4, "SWITCH", "F", "control",  "jetsonclaw1")
    op(0xE5, "COYIELD","F", "control",  "oracle1")
    op(0xE6, "CORESUM","F", "control",  "oracle1")
    op(0xE7, "FAULT",  "F", "system",   "jetsonclaw1")
    op(0xE8, "HANDLER","F", "system",   "jetsonclaw1")
    op(0xE9, "TRACE",  "F", "debug",    "converged")
    op(0xEA, "PROF_ON","F", "debug",    "jetsonclaw1")
    op(0xEB, "PROF_OFF","F","debug",    "jetsonclaw1")
    op(0xEC, "WATCH",  "F", "debug",    "converged")
    op(0xED, "RESERVED_ED","F","reserved","none", res=True)
    op(0xEE, "RESERVED_EE","F","reserved","none", res=True)
    op(0xEF, "RESERVED_EF","F","reserved","none", res=True)
    # 0xF0-0xFF: Extended System/Debug
    op(0xF0, "HALT_ERR","A","system",  "converged")
    op(0xF1, "REBOOT", "A", "system",  "jetsonclaw1")
    op(0xF2, "DUMP",   "A", "debug",   "converged")
    op(0xF3, "ASSERT", "A", "debug",   "converged")
    op(0xF4, "ID",     "A", "system",  "oracle1")
    op(0xF5, "VER",    "A", "system",  "converged")
    op(0xF6, "CLK",    "A", "system",  "jetsonclaw1")
    op(0xF7, "PCLK",   "A", "system",  "jetsonclaw1")
    op(0xF8, "WDOG",   "A", "system",  "jetsonclaw1")
    op(0xF9, "SLEEP",  "A", "system",  "jetsonclaw1")
    op(0xFA, "RESERVED_FA","A","reserved","none", res=True)
    op(0xFB, "RESERVED_FB","A","reserved","none", res=True)
    op(0xFC, "RESERVED_FC","A","reserved","none", res=True)
    op(0xFD, "RESERVED_FD","A","reserved","none", res=True)
    op(0xFE, "RESERVED_FE","A","reserved","none", res=True)
    op(0xFF, "ILLEGAL","A","system",  "converged")
    return ops

CONVERGED_OPCODES = _build_converged()


# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

SOURCES = {
    "oracle1":   ORACLE1_OPCODES,
    "jc1":       JC1_OPCODES,
    "babel":     BABEL_OPCODES,
    "converged": CONVERGED_OPCODES,
}

SOURCE_LABELS = {
    "oracle1":   "Oracle1's Python VM (opcodes.py)",
    "jc1":       "JetsonClaw1's C VM (formats.py)",
    "babel":     "Babel's Multilingual (120 opcodes)",
    "converged": "Unified ISA (isa_unified.py, 247 opcodes)",
}

VALID_SOURCES = list(SOURCES.keys())


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_mnemonic(m: str) -> str:
    """Normalize a mnemonic for comparison (strip prefixes, lowercase)."""
    return m.lower().replace("_", "").replace(".", "")


def semantically_match(a: str, b: str) -> bool:
    """Check if two mnemonics are semantically the same operation."""
    na, nb = normalize_mnemonic(a), normalize_mnemonic(b)
    if na == nb:
        return True
    # Handle common naming differences
    aliases = {
        "iadd": "add", "isub": "sub", "imul": "mul", "idiv": "div",
        "imod": "mod", "irem": "rem", "iand": "and", "ior": "or",
        "ixor": "xor", "inot": "not", "ishl": "shl", "ishr": "shr",
        "ineg": "neg", "icmp": "cmpeq", "confld": "confload", "confst": "confstore",
        "confload": "confld", "confstore": "confst",
        "storeoff": "storeof", "loadoff": "loadof",
        "vstore": "vstore", "vload": "vload",
    }
    return aliases.get(na, na) == aliases.get(nb, nb)


def opcode_size(fmt: str) -> int:
    return {"A": 1, "B": 2, "C": 2, "D": 3, "E": 4, "F": 4, "G": 5}.get(fmt, 0)


def format_bar(counts: dict, width: int = 40) -> str:
    """Create a simple ASCII bar chart."""
    if not counts:
        return ""
    max_val = max(counts.values()) if counts else 1
    lines = []
    for k in sorted(counts.keys()):
        bar_len = int(counts[k] / max_val * width) if max_val else 0
        bar = "#" * bar_len
        lines.append(f"  {k:16s} {bar} {counts[k]}")
    return "\n".join(lines)


def emoji_source(src: str) -> str:
    return {
        "oracle1": "🔮", "jetsonclaw1": "⚡", "babel": "🌐",
        "converged": "✅", "jc1": "⚡", "none": "—",
    }.get(src, "?")


def bold(s: str) -> str:
    return f"**{s}**"


# ═══════════════════════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_list(args):
    """List all opcodes in a given ISA source."""
    source = args.source
    if source not in SOURCES:
        print(f"Error: Unknown source '{source}'. Valid: {', '.join(VALID_SOURCES)}")
        sys.exit(1)

    ops = SOURCES[source]
    label = SOURCE_LABELS[source]

    # Apply filters
    if args.category:
        ops = [o for o in ops if o["category"] == args.category]
    if args.format:
        ops = [o for o in ops if o["format"] == args.format.upper()]
    if args.confidence_only:
        ops = [o for o in ops if o.get("confidence")]
    if args.defined_only and source == "converged":
        ops = [o for o in ops if not o.get("reserved")]

    lines = [
        f"# ISA Source: {label}",
        f"**Total opcodes:** {len(ops)}\n",
    ]

    if args.category:
        lines.append(f"*Filtered by category: `{args.category}`*\n")
    if args.format:
        lines.append(f"*Filtered by format: `{args.format.upper()}`*\n")

    lines.append("| Hex   | Mnemonic   | Fmt | Category    | Confidence |")
    lines.append("|-------|------------|-----|-------------|------------|")

    for o in sorted(ops, key=lambda x: x["hex"]):
        conf = "🔒" if o.get("confidence") else ""
        res = " ⛔" if o.get("reserved") else ""
        lines.append(
            f"| 0x{o['hex']:02X} | {o['mnemonic']:10s} | {o['format']}   "
            f"| {o['category']:11s} | {conf}{res}         |"
        )

    print("\n".join(lines))


def cmd_diff(args):
    """Show opcodes in source1 but not source2 and vice versa."""
    src1, src2 = args.source1, args.source2
    if src1 not in SOURCES:
        print(f"Error: Unknown source '{src1}'. Valid: {', '.join(VALID_SOURCES)}")
        sys.exit(1)
    if src2 not in SOURCES:
        print(f"Error: Unknown source '{src2}'. Valid: {', '.join(VALID_SOURCES)}")
        sys.exit(1)

    ops1 = SOURCES[src1]
    ops2 = SOURCES[src2]

    label1 = SOURCE_LABELS[src1]
    label2 = SOURCE_LABELS[src2]

    # Build normalized lookup for source2
    s2_by_name = {normalize_mnemonic(o["mnemonic"]): o for o in ops2}
    s2_by_hex = {o["hex"]: o for o in ops2}

    s1_by_name = {normalize_mnemonic(o["mnemonic"]): o for o in ops1}
    s1_by_hex = {o["hex"]: o for o in ops1}

    # Find opcodes in source1 but NOT semantically in source2
    only_in_1 = []
    for o in ops1:
        n = normalize_mnemonic(o["mnemonic"])
        if n not in s2_by_name and o["hex"] not in s2_by_hex:
            # Also check semantic aliases
            found = False
            for s2n in s2_by_name:
                if semantically_match(o["mnemonic"], s2_by_name[s2n]["mnemonic"]):
                    found = True
                    break
            if not found:
                only_in_1.append(o)

    # Find opcodes in source2 but NOT semantically in source1
    only_in_2 = []
    for o in ops2:
        n = normalize_mnemonic(o["mnemonic"])
        if n not in s1_by_name and o["hex"] not in s1_by_hex:
            found = False
            for s1n in s1_by_name:
                if semantically_match(o["mnemonic"], s1_by_name[s1n]["mnemonic"]):
                    found = True
                    break
            if not found:
                only_in_2.append(o)

    # Find matches (same mnemonic, different hex)
    matches = []
    for o in ops1:
        for o2 in ops2:
            if semantically_match(o["mnemonic"], o2["mnemonic"]):
                if o["hex"] != o2["hex"]:
                    matches.append((o, o2))
                break

    # Find conflicts (same hex, different mnemonic)
    conflicts = []
    for o in ops1:
        if o["hex"] in s2_by_hex:
            o2 = s2_by_hex[o["hex"]]
            if not semantically_match(o["mnemonic"], o2["mnemonic"]):
                conflicts.append((o, o2))

    lines = [
        f"# ISA Diff: {src1} vs {src2}",
        f"**{label1}**",
        f"**{label2}**\n",
        f"## Summary\n",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| {src1} total | {len(ops1)} |",
        f"| {src2} total | {len(ops2)} |",
        f"| Only in {src1} | {len(only_in_1)} |",
        f"| Only in {src2} | {len(only_in_2)} |",
        f"| Semantic matches (different encoding) | {len(matches)} |",
        f"| Hex conflicts (same code, different op) | {len(conflicts)} |",
    ]

    if matches:
        lines.append(f"\n## Semantic Matches (different encoding)\n")
        lines.append(f"| {src1} Mnemonic | {src1} Hex | {src2} Mnemonic | {src2} Hex | Category |")
        lines.append(f"|---------------|-----------|---------------|-----------|----------|")
        for o1, o2 in sorted(matches, key=lambda x: x[0]["hex"]):
            lines.append(
                f"| {o1['mnemonic']:14s} | 0x{o1['hex']:02X}     "
                f"| {o2['mnemonic']:14s} | 0x{o2['hex']:02X}     | {o1['category']} |"
            )

    if only_in_1:
        lines.append(f"\n## Only in `{src1}` ({len(only_in_1)} opcodes)\n")
        lines.append(f"| Hex   | Mnemonic   | Category    | Description |")
        lines.append(f"|-------|------------|-------------|-------------|")
        for o in sorted(only_in_1, key=lambda x: x["hex"]):
            lines.append(f"| 0x{o['hex']:02X} | {o['mnemonic']:10s} | {o['category']:11s} | {o.get('description','')[:40]} |")

    if only_in_2:
        lines.append(f"\n## Only in `{src2}` ({len(only_in_2)} opcodes)\n")
        lines.append(f"| Hex   | Mnemonic   | Category    | Description |")
        lines.append(f"|-------|------------|-------------|-------------|")
        for o in sorted(only_in_2, key=lambda x: x["hex"]):
            lines.append(f"| 0x{o['hex']:02X} | {o['mnemonic']:10s} | {o['category']:11s} | {o.get('description','')[:40]} |")

    if conflicts:
        lines.append(f"\n## ⚠️ Hex Conflicts (same code, different opcodes)\n")
        lines.append(f"| Hex   | {src1} Mnemonic | {src2} Mnemonic |")
        lines.append(f"|-------|---------------|---------------|")
        for o1, o2 in sorted(conflicts, key=lambda x: x[0]["hex"]):
            lines.append(f"| 0x{o1['hex']:02X} | {o1['mnemonic']:14s} | {o2['mnemonic']:14s} |")

    print("\n".join(lines))


def cmd_stats(args):
    """Show statistics about each ISA source."""
    if args.source:
        targets = {args.source: SOURCES[args.source]}
        labels = {args.source: SOURCE_LABELS[args.source]}
    else:
        targets = SOURCES
        labels = SOURCE_LABELS

    for name, ops in targets.items():
        defined = [o for o in ops if not o.get("reserved")]
        reserved = [o for o in ops if o.get("reserved")]
        conf_ops = [o for o in defined if o.get("confidence")]

        by_fmt = Counter(o["format"] for o in defined)
        by_cat = Counter(o["category"] for o in defined)
        by_src = Counter(o["source"] for o in defined) if name == "converged" else {}

        lines = [
            f"# Statistics: {labels[name]}",
            f"",
            f"## Overview\n",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total slots | {len(ops)} |",
            f"| Defined opcodes | {len(defined)} |",
            f"| Reserved | {len(reserved)} |",
            f"| Confidence-aware | {len(conf_ops)} |",
            f"| Categories | {len(by_cat)} |",
            f"| Formats used | {len(by_fmt)} |",
        ]

        # Format distribution
        lines.append(f"\n## Format Distribution\n")
        lines.append(f"| Format | Count | Bytes each | Total bytes |")
        lines.append(f"|--------|-------|-------------|-------------|")
        total_bytes = 0
        for fmt in ["A", "B", "C", "D", "E", "F", "G"]:
            c = by_fmt.get(fmt, 0)
            sz = opcode_size(fmt)
            total_bytes += c * sz
            lines.append(f"| {fmt} | {c} | {sz} | {c * sz} |")
        lines.append(f"| **Total** | **{len(defined)}** | | **{total_bytes}** |")

        # Category distribution
        lines.append(f"\n## Category Distribution\n")
        lines.append(format_bar(by_cat))

        # Source distribution (converged only)
        if name == "converged" and by_src:
            lines.append(f"\n## Source Attribution (converged ISA)\n")
            lines.append(f"| Source | Count | Percentage |")
            lines.append(f"|--------|-------|------------|")
            for src, count in sorted(by_src.items(), key=lambda x: -x[1]):
                pct = count / len(defined) * 100 if defined else 0
                lines.append(f"| {emoji_source(src)} {src} | {count} | {pct:.1f}% |")

        # Opcode density analysis
        if defined:
            hex_vals = [o["hex"] for o in defined]
            space_min, space_max = min(hex_vals), max(hex_vals)
            span = space_max - space_min + 1
            density = len(defined) / span * 100
            lines.append(f"\n## Opcode Space Analysis\n")
            lines.append(f"| Metric | Value |")
            lines.append(f"|--------|-------|")
            lines.append(f"| Lowest opcode | 0x{space_min:02X} |")
            lines.append(f"| Highest opcode | 0x{space_max:02X} |")
            lines.append(f"| Address span | {span} slots |")
            lines.append(f"| Density | {density:.1f}% |")

        print("\n".join(lines))
        if len(targets) > 1:
            print("\n---\n")


def cmd_converge(args):
    """Show convergence status across all sources."""
    conv_ops = [o for o in CONVERGED_OPCODES if not o.get("reserved")]
    conv_names = {normalize_mnemonic(o["mnemonic"]): o for o in conv_ops}
    conv_hexes = set(o["hex"] for o in conv_ops)

    sources_data = {
        "oracle1": ORACLE1_OPCODES,
        "jc1":     JC1_OPCODES,
        "babel":   BABEL_OPCODES,
    }

    lines = [
        "# ISA Convergence Status",
        "",
        "Analysis of convergence between the three fleet ISA sources",
        f"and the target unified ISA ({len(conv_ops)} defined opcodes).\n",
    ]

    # Per-source coverage
    lines.append("## Per-Source Coverage\n")
    lines.append("| Source | Opcodes | Covered in Converged | Coverage |")
    lines.append("|--------|---------|---------------------|----------|")

    total_covered = 0
    total_ops = 0
    uncovered_by_source = {}

    for name, ops in sources_data.items():
        covered = 0
        uncovered = []
        for o in ops:
            n = normalize_mnemonic(o["mnemonic"])
            found = n in conv_names
            if not found:
                for cn in conv_names:
                    if semantically_match(o["mnemonic"], cn):
                        found = True
                        break
            if found:
                covered += 1
            else:
                uncovered.append(o)
        total = len(ops)
        pct = covered / total * 100 if total else 0
        total_covered += covered
        total_ops += total
        uncovered_by_source[name] = uncovered
        lines.append(f"| {emoji_source(name)} {name} | {total} | {covered} | {pct:.1f}% |")

    # Overall convergence
    overall_pct = total_covered / total_ops * 100 if total_ops else 0
    lines.append(f"| **Total** | **{total_ops}** | **{total_covered}** | **{overall_pct:.1f}%** |")

    # Uncovered opcodes detail
    has_uncovered = False
    for name, uncovered in uncovered_by_source.items():
        if uncovered:
            has_uncovered = True
            break

    if has_uncovered:
        lines.append("\n## Uncovered Opcodes (not yet in converged ISA)\n")
        for name, uncovered in uncovered_by_source.items():
            if not uncovered:
                continue
            lines.append(f"### {emoji_source(name)} `{name}` — {len(uncovered)} uncovered\n")
            lines.append("| Hex   | Mnemonic   | Category    | Description |")
            lines.append("|-------|------------|-------------|-------------|")
            for o in sorted(uncovered, key=lambda x: x["hex"]):
                lines.append(
                    f"| 0x{o['hex']:02X} | {o['mnemonic']:10s} | {o['category']:11s} "
                    f"| {o.get('description','')[:40]} |"
                )
            lines.append("")

    # Source attribution in converged ISA
    by_src = Counter(o["source"] for o in conv_ops)
    lines.append("## Converged ISA Source Attribution\n")
    lines.append("| Source | Opcodes | Percentage |")
    lines.append("|--------|---------|------------|")
    for src, count in sorted(by_src.items(), key=lambda x: -x[1]):
        pct = count / len(conv_ops) * 100
        lines.append(f"| {emoji_source(src)} {src} | {count} | {pct:.1f}% |")

    # Category coverage matrix
    lines.append("\n## Category Coverage Matrix\n")
    all_cats = sorted(set(
        o["category"] for ops in sources_data.values() for o in ops
    ) | set(o["category"] for o in conv_ops))

    header = "| Category | " + " | ".join(f"{emoji_source(s)} {s}" for s in sources_data) + " | converged |"
    sep = "|----------|" + "|".join("---" for _ in sources_data) + "|-----------|"
    lines.append(header)
    lines.append(sep)

    for cat in all_cats:
        row = f"| {cat:12s} |"
        for name in sources_data:
            c = sum(1 for o in sources_data[name] if o["category"] == cat)
            row += f" {c:5d} |"
        c = sum(1 for o in conv_ops if o["category"] == cat)
        row += f" {c:9d} |"
        lines.append(row)

    # Convergence verdict
    lines.append(f"\n## Convergence Verdict\n")
    if overall_pct >= 95:
        verdict = "✅ NEAR-COMPLETE — All critical operations are converged"
    elif overall_pct >= 80:
        verdict = "🟡 SUBSTANTIAL — Core operations converged, edge cases remain"
    elif overall_pct >= 60:
        verdict = "🟠 IN-PROGRESS — Significant gaps require attention"
    else:
        verdict = "🔴 EARLY — Major convergence work needed"

    lines.append(f"- **Overall coverage:** {overall_pct:.1f}%")
    lines.append(f"- **Verdict:** {verdict}")
    lines.append(f"- **Converged ISA size:** {len(conv_ops)} opcodes (256 total slots)")
    lines.append(f"- **Remaining slots:** {256 - len(conv_ops)}")

    print("\n".join(lines))


def cmd_verify(args):
    """Verify that the converged ISA covers all base operations."""
    # Define critical base operations that MUST be covered
    base_requirements = {
        "system": {
            "HALT": "Stop execution",
            "NOP": "No operation",
            "RET": "Return from subroutine",
        },
        "arithmetic": {
            "ADD": "Integer add",
            "SUB": "Integer subtract",
            "MUL": "Integer multiply",
            "DIV": "Integer divide",
            "MOD": "Integer modulo",
            "INC": "Increment",
            "DEC": "Decrement",
            "NEG": "Negate",
        },
        "logic": {
            "AND": "Bitwise AND",
            "OR": "Bitwise OR",
            "XOR": "Bitwise XOR",
            "NOT": "Bitwise NOT",
            "SHL": "Shift left",
            "SHR": "Shift right",
        },
        "compare": {
            "CMP_EQ": "Compare equal",
            "CMP_LT": "Compare less than",
            "CMP_GT": "Compare greater than",
            "CMP_NE": "Compare not equal",
        },
        "memory": {
            "LOAD": "Load from memory",
            "STORE": "Store to memory",
            "MOV": "Register move",
        },
        "control": {
            "JMP": "Unconditional jump",
            "JZ": "Jump if zero",
            "JNZ": "Jump if not zero",
            "JAL": "Jump and link",
            "CALL": "Call subroutine",
        },
        "stack": {
            "PUSH": "Push to stack",
            "POP": "Pop from stack",
        },
        "float": {
            "FADD": "Float add",
            "FSUB": "Float subtract",
            "FMUL": "Float multiply",
            "FDIV": "Float divide",
        },
        "a2a": {
            "TELL": "Send message to agent",
            "ASK": "Request from agent",
            "DELEG": "Delegate task",
            "BCAST": "Broadcast",
        },
        "move": {
            "MOVI": "Move immediate",
            "MOVI16": "Move 16-bit immediate",
        },
    }

    conv_ops = [o for o in CONVERGED_OPCODES if not o.get("reserved")]
    conv_names = {normalize_mnemonic(o["mnemonic"]): o for o in conv_ops}

    lines = [
        "# ISA Verification Report",
        "",
        "Verifying that the converged ISA covers all required base operations.\n",
    ]

    all_pass = True
    total_required = 0
    total_found = 0
    missing_ops = []

    for category, reqs in base_requirements.items():
        lines.append(f"## {category.upper()}\n")
        lines.append("| Required | Status | Converged Mnemonic | Hex |")
        lines.append("|----------|--------|--------------------|----|")

        for req_mnem, req_desc in reqs.items():
            total_required += 1
            found = False
            match_mnem = ""
            match_hex = ""

            # Check exact match
            n = normalize_mnemonic(req_mnem)
            if n in conv_names:
                found = True
                match_mnem = conv_names[n]["mnemonic"]
                match_hex = conv_names[n]["hex"]
            else:
                # Check semantic match
                for o in conv_ops:
                    if semantically_match(req_mnem, o["mnemonic"]):
                        found = True
                        match_mnem = o["mnemonic"]
                        match_hex = o["hex"]
                        break

            if found:
                total_found += 1
                lines.append(
                    f"| {req_mnem:10s} | ✅ OK  | {match_mnem:18s} | 0x{match_hex:02X} |"
                )
            else:
                all_pass = False
                missing_ops.append((category, req_mnem, req_desc))
                lines.append(f"| {req_mnem:10s} | ❌ MISSING | — | — |")

        lines.append("")

    # Format coverage
    lines.append("## Format Coverage\n")
    lines.append("| Format | Used in Converged | Required by Any Source |")
    lines.append("|--------|-------------------|------------------------|")

    for fmt in ["A", "B", "C", "D", "E", "F", "G"]:
        in_conv = sum(1 for o in conv_ops if o["format"] == fmt)
        # Check if any source uses this format
        used_anywhere = any(
            sum(1 for o in ops if o["format"] == fmt) > 0
            for ops in [ORACLE1_OPCODES, JC1_OPCODES, BABEL_OPCODES]
        )
        status = "✅" if in_conv > 0 else "❌"
        req = "Yes" if used_anywhere else "—"
        lines.append(f"| {fmt} | {in_conv:3d} | {req:6s} {status} |")

    # Summary
    coverage_pct = total_found / total_required * 100 if total_required else 0
    lines.append(f"## Summary\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Required operations | {total_required} |")
    lines.append(f"| Found in converged | {total_found} |")
    lines.append(f"| Missing | {len(missing_ops)} |")
    lines.append(f"| Coverage | {coverage_pct:.1f}% |")
    lines.append(f"| Status | {'✅ PASS' if all_pass else '❌ FAIL'} |")

    if missing_ops:
        lines.append(f"\n### Missing Operations\n")
        lines.append("| Category | Mnemonic | Description |")
        lines.append("|----------|----------|-------------|")
        for cat, mnem, desc in missing_ops:
            lines.append(f"| {cat} | {mnem} | {desc} |")

    print("\n".join(lines))


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="flux-isa-diff",
        description="FLUX ISA Convergence CLI — Compare, diff, and analyze ISA definitions across the SuperInstance fleet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list --source converged --category arithmetic
  %(prog)s list --source oracle1 --format B
  %(prog)s diff oracle1 jc1
  %(prog)s diff oracle1 converged
  %(prog)s stats
  %(prog)s stats --source babel
  %(prog)s converge
  %(prog)s verify

Sources:
  oracle1   Oracle1's Python VM (opcodes.py, ~80 opcodes)
  jc1       JetsonClaw1's C VM (formats.py, ~67 opcodes)
  babel     Babel's Multilingual (120 opcodes including 16 viewpoint)
  converged Unified ISA (isa_unified.py, 247 opcodes — target)
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list command
    list_parser = subparsers.add_parser("list", help="List opcodes in an ISA source")
    list_parser.add_argument(
        "--source", "-s",
        choices=VALID_SOURCES,
        default="converged",
        help="ISA source to list (default: converged)",
    )
    list_parser.add_argument(
        "--category", "-c",
        help="Filter by category (e.g., arithmetic, float, a2a)",
    )
    list_parser.add_argument(
        "--format", "-f",
        help="Filter by format (A through G)",
    )
    list_parser.add_argument(
        "--confidence-only",
        action="store_true",
        help="Show only confidence-aware opcodes",
    )
    list_parser.add_argument(
        "--defined-only",
        action="store_true",
        help="Exclude reserved slots (converged source only)",
    )

    # diff command
    diff_parser = subparsers.add_parser("diff", help="Diff two ISA sources")
    diff_parser.add_argument(
        "source1",
        choices=VALID_SOURCES,
        help="First ISA source",
    )
    diff_parser.add_argument(
        "source2",
        choices=VALID_SOURCES,
        help="Second ISA source",
    )

    # stats command
    stats_parser = subparsers.add_parser("stats", help="Show ISA statistics")
    stats_parser.add_argument(
        "--source", "-s",
        choices=VALID_SOURCES,
        default=None,
        help="Source to show stats for (default: all sources)",
    )

    # converge command
    subparsers.add_parser(
        "converge",
        help="Show convergence status across all sources",
    )

    # verify command
    subparsers.add_parser(
        "verify",
        help="Verify converged ISA covers all base operations",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "list":
        cmd_list(args)
    elif args.command == "diff":
        cmd_diff(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "converge":
        cmd_converge(args)
    elif args.command == "verify":
        cmd_verify(args)


if __name__ == "__main__":
    main()
