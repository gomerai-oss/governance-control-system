"""Pack writer (spec section 3): assembles an evidence pack directory.

A pack is a directory holding:

- ``layout.json``: the HITL-signed layout for the mission
- ``<STEP>.link``: one signed link per layout step
- ``provenance.json``: an in-toto Statement with a SLSA v1 provenance predicate
  recording who acted, from what input, by what process, under what authority

The writer checks shape only: one link per layout step, nothing extra. It does
not judge signatures or the chain; that is the verifier's job, and the verifier
shares no code with this module beyond the file formats.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

from epap import layout as layout_model
from epap.signing import dump, sha256_hex

LAYOUT_FILE = "layout.json"
PROVENANCE_FILE = "provenance.json"
LINK_SUFFIX = ".link"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "urn:epap:pipeline:" + layout_model.PIPELINE_ID
DEFAULT_BUILDER_ID = "urn:epap:mission-router"


class PackError(ValueError):
    pass


def link_file(step_name: str) -> str:
    return step_name + LINK_SUFFIX


def _descriptors(artifacts: Mapping[str, Mapping[str, str]]) -> list:
    return [{"name": path, "digest": {"sha256": artifacts[path]["sha256"]}} for path in sorted(artifacts)]


def build_provenance(layout_doc: Mapping, layout_bytes: bytes, links: Sequence[Mapping],
                     link_bytes: Sequence[bytes], authority: Mapping, builder_id: str) -> dict:
    signed_layout = layout_doc["signed"]
    keys = signed_layout["keys"]
    steps = []
    for model, doc, raw in zip(layout_model.STEPS, links, link_bytes):
        actor = doc["signatures"][0]["keyid"]
        steps.append({
            "name": model.name,
            "role": model.role,
            "actor": actor,
            "principal": dict(keys[actor]["principal"]) if actor in keys else None,
            "command": list(doc["signed"]["command"]),
            "link": link_file(model.name),
            "link_sha256": sha256_hex(raw),
        })
    return {
        "_type": STATEMENT_TYPE,
        "subject": _descriptors(links[-1]["signed"]["products"]),
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "mission_id": signed_layout["mission_id"],
                    "spec": layout_model.SPEC_ID,
                    "authority": dict(authority),
                },
                "internalParameters": {
                    "pipeline": layout_model.PIPELINE_ID,
                    "layout": LAYOUT_FILE,
                    "layout_sha256": sha256_hex(layout_bytes),
                    "steps": steps,
                },
                "resolvedDependencies": _descriptors(links[0]["signed"]["materials"]),
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": signed_layout["mission_id"]},
            },
        },
    }


def write_pack(pack_dir: Path, layout_doc: Mapping, link_docs: Sequence[Mapping], authority: Mapping,
               builder_id: str = DEFAULT_BUILDER_ID) -> Path:
    """Write a complete pack into ``pack_dir`` (which must be absent or empty)."""
    pack_dir = Path(pack_dir)
    if not isinstance(authority, Mapping) or not authority:
        raise PackError("provenance needs the authority the pipeline ran under")
    by_name = {}
    for doc in link_docs:
        name = doc["signed"]["name"]
        if name in by_name:
            raise PackError(f"two links for step {name}")
        if not doc.get("signatures"):
            raise PackError(f"link {name} is unsigned")
        by_name[name] = doc
    missing = [n for n in layout_model.STEP_NAMES if n not in by_name]
    extra = sorted(set(by_name) - set(layout_model.STEP_NAMES))
    if missing or extra:
        raise PackError(f"links must cover the layout exactly; missing {missing}, extra {extra}")
    if pack_dir.is_symlink() or (pack_dir.exists() and (not pack_dir.is_dir() or any(pack_dir.iterdir()))):
        raise PackError(f"{pack_dir} must be absent or an empty directory")
    ordered = [by_name[n] for n in layout_model.STEP_NAMES]

    layout_bytes = dump(dict(layout_doc))
    link_bytes = [dump(dict(doc)) for doc in ordered]
    provenance = build_provenance(layout_doc, layout_bytes, ordered, link_bytes, authority, builder_id)

    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / LAYOUT_FILE).write_bytes(layout_bytes)
    for name, raw in zip(layout_model.STEP_NAMES, link_bytes):
        (pack_dir / link_file(name)).write_bytes(raw)
    (pack_dir / PROVENANCE_FILE).write_bytes(dump(provenance))
    return pack_dir
