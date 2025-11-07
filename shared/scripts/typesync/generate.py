#!/usr/bin/env python
"""Lightweight schema -> types synchronizer.

Current scope: trade_signal.schema.json -> update autogen blocks in:
  - python: repo/shared/python/src/shared_python/types.py
  - rust:   repo/shared/rust/src/types.rs
  - ts:     repo/shared/react/src/types/trading.ts

Usage:
  python generate.py            # rewrite files in-place
  python generate.py --check    # exit 1 if changes would be produced
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any

ROOT = Path(__file__).resolve().parents[4]  # fks/ root
SCHEMA_DIR = ROOT / "repo" / "shared" / "schema"


@dataclass
class TradeSignalSpec:
    properties: Dict[str, Any]
    required: set[str]

    @classmethod
    def from_schema(cls, schema: Dict[str, Any]):
        return cls(properties=schema.get("properties", {}), required=set(schema.get("required", [])))


MARKER_START = "<types:autogen start>"
MARKER_END = "<types:autogen end>"


def gen_python(spec: TradeSignalSpec) -> str:
    lines = ["class TradeSignal(BaseModel):", "    \"\"\"Auto-generated from trade_signal.schema.json\"\"\""]
    enum_side = spec.properties.get("side", {}).get("enum", [])
    for name, prop in spec.properties.items():
        optional = name not in spec.required
        typ = "str"
        if name == "strength":
            typ = "float"
        elif name == "timestamp":
            typ = "datetime"
        elif name == "meta":
            typ = "dict | None" if optional else "dict"
        elif enum_side and name == "side":
            # Python Literal expects comma-separated values: Literal["A", "B"], not pipes
            lit = ", ".join([f'"{v}"' for v in enum_side])
            typ = f"Literal[{lit}]"
        field_decl = f"    {name}: {typ}"
        if name == "strength":
            minimum = prop.get("minimum")
            maximum = prop.get("maximum")
            field_decl += f" = Field(ge={minimum}, le={maximum})"
        lines.append(field_decl)
    return "\n".join(lines)


def gen_rust(spec: TradeSignalSpec) -> str:
    enum_side = spec.properties.get("side", {}).get("enum", [])
    enum_block = ["#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]", "pub enum TradeSide {", *[f"    {v}," for v in enum_side], "}"]
    struct_lines = ["#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]", "pub struct TradeSignal {",]
    for name, prop in spec.properties.items():
        if name == "side":
            rust_type = "TradeSide"
        elif name == "strength":
            rust_type = "f64"
        elif name == "timestamp":
            rust_type = "String"  # ISO8601
        elif name == "meta":
            rust_type = "Option<serde_json::Value>"
        else:
            rust_type = "String"
        struct_lines.append(f"    pub {name}: {rust_type},")
    struct_lines.append("}")
    return "\n".join(struct_lines + ["", *enum_block])


def gen_ts(spec: TradeSignalSpec) -> str:
    enum_side = spec.properties.get("side", {}).get("enum", [])
    lines = ["export interface TradeSignal {"]
    for name, prop in spec.properties.items():
        optional = name not in spec.required
        if name == "side" and enum_side:
            ts_type = " | ".join([f"'{v}'" for v in enum_side])
        elif name == "strength":
            ts_type = "number"
        elif name == "timestamp":
            ts_type = "string"  # ISO8601
        elif name == "meta":
            ts_type = "Record<string, unknown>"
        else:
            ts_type = "string"
        q = "?" if optional else ""
        comment = " // 0..1" if name == "strength" else ""
        lines.append(f"  {name}{q}: {ts_type};{comment}")
    lines.append("}")
    return "\n".join(lines)


def replace_block(content: str, new_block: str) -> str:
    pattern = re.compile(rf"(//|#)?\s*{re.escape(MARKER_START)}(.*?){re.escape(MARKER_END)}", re.DOTALL)
    def _repl(match):
        prefix = match.group(1) or ""
        start_line = f"{prefix} {MARKER_START}".strip()
        end_line = f"{prefix} {MARKER_END}".strip()
        return f"{start_line}\n{new_block}\n{end_line}"
    return pattern.sub(_repl, content, count=1)


def process(schema_file: Path, write: bool, check: bool) -> int:
    schema = json.loads(schema_file.read_text())
    spec = TradeSignalSpec.from_schema(schema)
    py_file = ROOT / "repo" / "shared" / "python" / "src" / "shared_python" / "types.py"
    py_content = py_file.read_text()
    py_block = gen_python(spec)
    py_new = replace_block(py_content, py_block)

    rs_file = ROOT / "repo" / "shared" / "rust" / "src" / "types.rs"
    rs_content = rs_file.read_text()
    rs_block = gen_rust(spec)
    rs_new = replace_block(rs_content, rs_block)

    ts_file = ROOT / "repo" / "shared" / "react" / "src" / "types" / "trading.ts"
    ts_content = ts_file.read_text()
    ts_block = gen_ts(spec)
    ts_new = replace_block(ts_content, ts_block)

    changed = (py_new != py_content) or (rs_new != rs_content) or (ts_new != ts_content)

    if check and changed:
        return 1
    if write and changed:
        py_file.write_text(py_new)
        rs_file.write_text(rs_new)
        ts_file.write_text(ts_new)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if changes would be made")
    args = parser.parse_args()
    schema_file = SCHEMA_DIR / "trade_signal.schema.json"
    if not schema_file.exists():
        raise SystemExit(f"Schema not found: {schema_file}")
    code = process(schema_file, write=not args.check, check=args.check)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
