# Type Synchronization

Prototype process for generating language-specific types from JSON Schemas in `repo/shared/schema`.

Planned flow:
1. Author/update schema (e.g. `trade_signal.schema.json`).
2. Run `./repo/shared/scripts/typesync/generate.sh` to emit:
   - Python Pydantic model file (overwriting `types.py` section guarded by markers)
   - Rust struct + enum (overwriting region in `types.rs`)
   - TypeScript interface (already matches; future: regeneration with doc comments)

Markers (example):
```python
# <types:autogen start>
# ... generated content ...
# <types:autogen end>
```

The current script is a stub; integrate tools like `quicktype` or `datamodel-code-generator` later.
