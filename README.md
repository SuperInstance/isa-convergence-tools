# ISA Convergence Tools

CLI tools for comparing, diffing, and converging FLUX ISA definitions across the SuperInstance fleet.

## Background

The SuperInstance fleet has three independent ISA implementations that need convergence:

| Agent | Source File | Opcodes | Notes |
|-------|------------|---------|-------|
| 🔮 Oracle1 | `opcodes.py` | ~80 | Python VM, variable-length encoding |
| ⚡ JetsonClaw1 | `formats.py` | ~67 | C VM, unified encoding formats A-G |
| 🌐 Babel | (multilingual) | 120 | Includes 16 viewpoint ops |
| ✅ Converged | `isa_unified.py` | 247 | The target unified ISA |

## Installation

```bash
# No dependencies — just make it executable
chmod +x flux-isa-diff.py
# Or run directly with Python 3
python3 flux-isa-diff.py --help
```

## Usage

### `list` — List opcodes in an ISA source

```bash
# List all converged opcodes
./flux-isa-diff.py list

# List oracle1's opcodes
./flux-isa-diff.py list --source oracle1

# Filter by category
./flux-isa-diff.py list --source converged --category arithmetic
./flux-isa-diff.py list --source converged --category viewpoint

# Filter by format
./flux-isa-diff.py list --source jc1 --format E

# Only confidence-aware opcodes
./flux-isa-diff.py list --source converged --confidence-only
```

### `diff` — Compare two ISA sources

```bash
# Show differences between oracle1 and jc1
./flux-isa-diff.py diff oracle1 jc1

# See what oracle1 has that converged doesn't (and vice versa)
./flux-isa-diff.py diff oracle1 converged

# Compare any two sources
./flux-isa-diff.py diff babel jc1
./flux-isa-diff.py diff babel converged
```

Output includes:
- Semantic matches (same operation, different encoding)
- Opcodes unique to each source
- Hex conflicts (same code, different operation)

### `stats` — Show ISA statistics

```bash
# Stats for all sources
./flux-isa-diff.py stats

# Stats for a single source
./flux-isa-diff.py stats --source converged
./flux-isa-diff.py stats --source oracle1
```

Output includes:
- Opcode counts (defined, reserved, confidence-aware)
- Format distribution (A through G) with byte totals
- Category distribution with ASCII bar charts
- Source attribution (for converged ISA)
- Opcode space density analysis

### `converge` — Show convergence status

```bash
./flux-isa-diff.py converge
```

Output includes:
- Per-source coverage percentage
- Uncovered opcodes per source
- Source attribution in the converged ISA
- Category coverage matrix across all sources
- Convergence verdict (NEAR-COMPLETE / SUBSTANTIAL / IN-PROGRESS / EARLY)

### `verify` — Verify base operation coverage

```bash
./flux-isa-diff.py verify
```

Checks that the converged ISA covers all critical base operations:
- System ops (HALT, NOP, RET)
- Arithmetic (ADD, SUB, MUL, DIV, MOD, INC, DEC, NEG)
- Logic (AND, OR, XOR, NOT, SHL, SHR)
- Compare (EQ, LT, GT, NE)
- Memory (LOAD, STORE, MOV)
- Control (JMP, JZ, JNZ, JAL, CALL)
- Stack (PUSH, POP)
- Float (FADD, FSUB, FMUL, FDIV)
- A2A (TELL, ASK, DELEG, BCAST)
- Move (MOVI, MOVI16)

Also verifies format coverage across all encoding formats A-G.

## Source Files

The tool embeds ISA data from three fleet source files:

- **`flux-runtime/src/flux/bytecode/opcodes.py`** — Oracle1's Python VM opcodes
- **`flux-runtime/src/flux/bytecode/formats.py`** — JetsonClaw1's encoding format reference
- **`flux-runtime/src/flux/bytecode/isa_unified.py`** — The converged unified ISA

## Encoding Format Reference

| Format | Size | Encoding | Examples |
|--------|------|----------|---------|
| A | 1 byte | `[op]` | HALT, NOP, RET |
| B | 2 bytes | `[op][rd]` | INC, DEC, PUSH, POP |
| C | 2 bytes | `[op][imm8]` | SYS, TRAP, DBG |
| D | 3 bytes | `[op][rd][imm8]` | MOVI, ADDI, SUBI |
| E | 4 bytes | `[op][rd][rs1][rs2]` | ADD, SUB, LOAD, STORE |
| F | 4 bytes | `[op][rd][imm16hi][imm16lo]` | MOVI16, JMP, JAL |
| G | 5 bytes | `[op][rd][rs1][imm16hi][imm16lo]` | LOADOFF, STOREOFF |

## License

Part of the SuperInstance fleet tooling.
