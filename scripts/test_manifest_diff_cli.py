"""Independent black-box oracle for rel-diff's controlled-input EX-02 pilot.

Synthetic manifests test the CLI/JSON contract, NOT PE extraction accuracy.
No supplied executable is launched: only the built rel-diff tool is executed.
"""
import argparse
import copy
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator

MAX_INPUT = 16 * 1024 * 1024


def manifest(sha, imports, exports, sections, *, size=1024, arch="x86"):
    return {
        "schema_version": "1.0.0",
        "binary_sha256": sha * 64,
        "size_bytes": size,
        "format": "PE",
        "arch": arch,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "warnings": [],
    }


def execute(binary, directory, left, right):
    left_path = directory / "left.json"
    right_path = directory / "right.json"
    left_path.write_text(json.dumps(left), encoding="utf-8")
    right_path.write_text(json.dumps(right), encoding="utf-8")
    return subprocess.run(
        [str(binary), str(left_path), str(right_path)],
        capture_output=True,
        check=False,
        timeout=30,
    )


def accepted(binary, directory, validator, left, right):
    completed = execute(binary, directory, left, right)
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    result = json.loads(completed.stdout)
    validator.validate(result)
    assert result["left_sha256"] == left["binary_sha256"]
    assert result["right_sha256"] == right["binary_sha256"]
    return result, completed.stdout


def rejected(binary, directory, left, right):
    completed = execute(binary, directory, left, right)
    assert completed.returncode != 0, "invalid input was accepted"
    assert not completed.stdout, "invalid input emitted a partial report"
    assert completed.stderr, "invalid input lacked diagnostics"


def inspect_real_fixture_pair(binary, inspector, directory, input_validator, output_validator):
    """Compare real rel-inspect manifests from the two controlled synthetic PEs."""
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    manifests = []
    for name in ("pe32-basic.exe", "pe64-basic.exe"):
        source = fixtures / name
        result = subprocess.run(
            [str(inspector), "analyze", str(source)],
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        manifest_data = json.loads(result.stdout)
        input_validator.validate(manifest_data)
        assert manifest_data["binary_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert not manifest_data["warnings"]
        manifests.append(manifest_data)
    left, right = manifests
    same, _ = accepted(binary, directory, output_validator, left, left)
    assert same["sections"]["status"] == "unchanged"
    assert not same["imports"]["added"] and not same["imports"]["removed"]
    forward, _ = accepted(binary, directory, output_validator, left, right)
    reverse, _ = accepted(binary, directory, output_validator, right, left)
    assert not forward["size_changed"] and forward["arch_changed"]
    assert forward["imports"]["added"] == ["KERNEL32.dll!GetTickCount64"]
    assert forward["imports"]["removed"] == ["KERNEL32.dll!GetTickCount"]
    assert not forward["exports"]["added"] and not forward["exports"]["removed"]
    assert forward["imports"]["added"] == reverse["imports"]["removed"]
    assert forward["imports"]["removed"] == reverse["imports"]["added"]



def verify_numeric_consumer_subset(binary, directory, schema, report_schema, baseline):
    """Schema-valid != accepted by the experimental u64-only consumer.

    Evaluate all numeric paths at zero and the u64 boundary, plus nullable RVA.
    Crucially, schema-valid out-of-range/integral-decimal forms must not emit
    a report, no matter which manifest is invalid.
    """
    fields = (
        ("size_bytes", lambda item, v: item.__setitem__("size_bytes", v)),
        ("sections.offset", lambda item, v: item["sections"][0].__setitem__("offset", v)),
        ("sections.size", lambda item, v: item["sections"][0].__setitem__("size", v)),
        ("sections.virtual_address",
         lambda item, v: item["sections"][0].__setitem__("virtual_address", v)),
    )
    for field, assign in fields:
        for value in (0, (1 << 64) - 1):
            candidate = copy.deepcopy(baseline)
            assign(candidate, value)
            schema.validate(candidate)
            try:
                accepted(binary, directory, report_schema, baseline, candidate)
            except AssertionError as error:
                raise AssertionError(f"{field}={value}: valid u64 rejected") from error
        for value in (1 << 64, 1.0):
            candidate = copy.deepcopy(baseline)
            assign(candidate, value)
            schema.validate(candidate)  # Valid according to Draft 2020-12.
            for left, right in ((baseline, candidate), (candidate, baseline)):
                try:
                    rejected(binary, directory, left, right)
                except AssertionError as error:
                    raise AssertionError(
                        f"{field}={value!r}: schema-valid unsupported value accepted"
                    ) from error
        candidate = copy.deepcopy(baseline)
        assign(candidate, -1)
        assert not schema.is_valid(candidate), f"{field}: negative must fail schema"
        rejected(binary, directory, baseline, candidate)

    nullable = copy.deepcopy(baseline)
    nullable["sections"][0]["virtual_address"] = None
    schema.validate(nullable)
    accepted(binary, directory, report_schema, baseline, nullable)


def verify_dense_escaped_metadata(binary, directory, input_validator, output_validator):
    """Independent sets/section oracle under dense and escaped metadata."""
    def named(prefix, index, padding):
        suffix = "\t\n\\é" if index % 17 == 0 else "_"
        return f"{prefix}{index:05d}{suffix}" + "X" * padding

    def section(index, changed=False):
        return {
            "name": named(".sec", index, 320),
            "offset": index * 64 + int(changed),
            "size": index % 31,
            "virtual_address": None if index % 19 == 0 else 4096 + index * 96,
        }

    left = manifest(
        "a",
        [f"Lib{i:05d}.DLL!{named('proc', i, 256)}" for i in range(2048)],
        [named("Exp", i, 256) for i in range(1536)],
        [section(i) for i in range(256)],
    )
    right = manifest(
        "b",
        [f"Lib{i:05d}.DLL!{named('proc', i, 256)}" for i in range(1024, 3072)],
        [named("Exp", i, 256) for i in range(768, 2304)],
        [section(i, i < 256) for i in range(128, 384)],
    )
    for candidate in (left, right):
        input_validator.validate(candidate)
        assert len(json.dumps(candidate).encode("utf-8")) < MAX_INPUT

    forward, forward_bytes = accepted(binary, directory, output_validator, left, right)
    backward, _ = accepted(binary, directory, output_validator, right, left)
    assert forward["sections"]["status"] == "changed"
    assert not forward["import_dll_case_only"]
    assert not forward["size_changed"] and not forward["arch_changed"]
    for field in ("imports", "exports"):
        a, b = set(left[field]), set(right[field])
        assert forward[field]["added"] == sorted(b - a)
        assert forward[field]["removed"] == sorted(a - b)
        assert backward[field]["added"] == forward[field]["removed"]
        assert backward[field]["removed"] == forward[field]["added"]

    a = {item["name"] for item in left["sections"]}
    b = {item["name"] for item in right["sections"]}
    assert forward["sections"]["added"] == sorted(b - a)
    assert forward["sections"]["removed"] == sorted(a - b)
    assert forward["sections"]["changed"] == sorted(a & b)
    assert backward["sections"]["added"] == forward["sections"]["removed"]
    assert backward["sections"]["removed"] == forward["sections"]["added"]
    assert backward["sections"]["changed"] == forward["sections"]["changed"]

    permuted_left, permuted_right = copy.deepcopy(left), copy.deepcopy(right)
    for item in (permuted_left, permuted_right):
        for field in ("imports", "exports", "sections"):
            item[field].reverse()
    _, permuted_bytes = accepted(
        binary, directory, output_validator, permuted_left, permuted_right
    )
    assert permuted_bytes == forward_bytes, "dense diff depends on input ordering"

    ambiguous_left = copy.deepcopy(left)
    ambiguous_left["sections"].append(copy.deepcopy(left["sections"][0]))
    ambiguous, _ = accepted(binary, directory, output_validator, ambiguous_left, right)
    assert ambiguous["sections"]["status"] == "ambiguous"
    assert not any(ambiguous["sections"][key] for key in ("added", "removed", "changed"))
    assert ambiguous["imports"] == forward["imports"]
    assert ambiguous["exports"] == forward["exports"]

    for field in ("imports", "exports"):
        duplicated = copy.deepcopy(left)
        duplicated[field].append(duplicated[field][0])
        input_validator.validate(duplicated)  # Schema permits repeated observations.
        rejected(binary, directory, duplicated, right)
        rejected(binary, directory, right, duplicated)


def verify(binary, inspector):
    root = Path(__file__).resolve().parents[1]
    contract = json.loads(
        (root / "contracts/experimental/manifest-diff.schema.json").read_text(
            encoding="utf-8"
        )
    )
    input_schema = json.loads(
        (root / "contracts/schemas/binary-manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(contract)
    output_validator = Draft202012Validator(contract)
    input_validator = Draft202012Validator(input_schema)

    text_a = {"name": ".text", "offset": 512, "size": 100, "virtual_address": 4096}
    text_b = {"name": ".text", "offset": 512, "size": 120, "virtual_address": 4096}
    resource = {"name": ".rsrc", "offset": 1024, "size": 30, "virtual_address": None}
    a = manifest(
        "a",
        ["KERNEL32.DLL!ReadFile", "USER32.dll!MessageBoxA"],
        ["Start", "Shared"],
        [text_a],
    )
    b = manifest(
        "b",
        ["kernel32.dll!ReadFile", "ADVAPI32.dll!RegOpenKeyA"],
        ["Entry", "Shared"],
        [resource, text_b],
        size=2048,
        arch="x86_64",
    )
    input_validator.validate(a)
    input_validator.validate(b)

    with tempfile.TemporaryDirectory(prefix="rel-diff-oracle-") as temp:
        directory = Path(temp)
        same, _ = accepted(binary, directory, output_validator, a, a)
        assert not same["size_changed"] and not same["arch_changed"]
        assert same["sections"]["status"] == "unchanged"
        assert all(not same[key]["added"] and not same[key]["removed"] for key in ("imports", "exports"))
        assert not same["import_dll_case_only"]

        # The independent contract must reject internally inconsistent statuses.
        impossible = copy.deepcopy(same)
        impossible["sections"]["status"] = "changed"
        assert not output_validator.is_valid(impossible)
        impossible = copy.deepcopy(same)
        impossible["sections"]["added"] = [".fake"]
        assert not output_validator.is_valid(impossible)

        ab, ab_bytes = accepted(binary, directory, output_validator, a, b)
        ba, _ = accepted(binary, directory, output_validator, b, a)
        assert ab["size_changed"] and ab["arch_changed"]
        assert ab["sections"]["status"] == "changed"
        assert ab["sections"]["added"] == [".rsrc"]
        assert ab["sections"]["removed"] == []
        assert ab["sections"]["changed"] == [".text"]
        assert ab["imports"]["added"] == ["ADVAPI32.dll!RegOpenKeyA", "kernel32.dll!ReadFile"]
        assert ab["imports"]["removed"] == ["KERNEL32.DLL!ReadFile", "USER32.dll!MessageBoxA"]
        assert ab["exports"]["added"] == ["Entry"]
        assert ab["exports"]["removed"] == ["Start"]
        assert not ab["import_dll_case_only"]
        for key in ("imports", "exports"):
            assert ab[key]["added"] == ba[key]["removed"]
            assert ab[key]["removed"] == ba[key]["added"]
        assert ab["sections"]["added"] == ba["sections"]["removed"]
        assert ab["sections"]["removed"] == ba["sections"]["added"]
        assert ab["sections"]["changed"] == ba["sections"]["changed"]

        # No report may depend on the ordering of set-like manifest arrays.
        shuffled_a = copy.deepcopy(a)
        shuffled_b = copy.deepcopy(b)
        for candidate in (shuffled_a, shuffled_b):
            candidate["imports"].reverse()
            candidate["exports"].reverse()
            candidate["sections"].reverse()
        _, shuffled_bytes = accepted(
            binary, directory, output_validator, shuffled_a, shuffled_b
        )
        assert ab_bytes == shuffled_bytes
        for _ in range(3):
            _, repeat = accepted(binary, directory, output_validator, a, b)
            assert repeat == ab_bytes

        case_b = copy.deepcopy(a)
        case_b["binary_sha256"] = "c" * 64
        case_b["imports"][0] = "kernel32.dll!ReadFile"
        only_case, _ = accepted(binary, directory, output_validator, a, case_b)
        assert only_case["import_dll_case_only"]
        assert only_case["imports"]["removed"] == ["KERNEL32.DLL!ReadFile"]
        assert only_case["imports"]["added"] == ["kernel32.dll!ReadFile"]

        # Rust uses ASCII-only DLL-prefix case normalization. A Unicode
        # case conversion must NOT silently equate distinct observed strings.
        unicode_a = copy.deepcopy(a)
        unicode_b = copy.deepcopy(a)
        unicode_a["imports"] = ["Ä.DLL!ReadFile"]
        unicode_b["imports"] = ["ä.dll!ReadFile"]
        unicode_b["binary_sha256"] = "e" * 64
        unicode_report, _ = accepted(
            binary, directory, output_validator, unicode_a, unicode_b
        )
        assert not unicode_report["import_dll_case_only"]
        assert unicode_report["imports"]["removed"] == ["Ä.DLL!ReadFile"]
        assert unicode_report["imports"]["added"] == ["ä.dll!ReadFile"]

        collision = copy.deepcopy(a)
        collision["imports"].append("kernel32.dll!ReadFile")
        ambiguous, _ = accepted(binary, directory, output_validator, collision, case_b)
        assert not ambiguous["import_dll_case_only"]

        duplicated_section = copy.deepcopy(a)
        duplicated_section["sections"].append(copy.deepcopy(text_a))
        no_match, _ = accepted(binary, directory, output_validator, duplicated_section, b)
        assert no_match["sections"]["status"] == "ambiguous"
        assert not any(no_match["sections"][key] for key in ("added", "removed", "changed"))

        invalid = []
        for change in (
            lambda v: v.update(schema_version="2.0.0"),
            lambda v: v.update(format="ELF"),
            lambda v: v.update(binary_sha256="A" * 64),
            lambda v: v.update(size_bytes=-1),
            lambda v: v.update(size_bytes=1.5),
            lambda v: v.update(imports=["X", "X"]),
            lambda v: v.update(warnings=["incomplete extraction"]),
            lambda v: v.pop("warnings"),
            lambda v: v.pop("arch"),
            lambda v: v.update(unexpected=1),
            lambda v: v["sections"][0].pop("virtual_address"),
            lambda v: v["sections"][0].update(size=-1),
        ):
            candidate = copy.deepcopy(a)
            change(candidate)
            invalid.append(candidate)
        for index, candidate in enumerate(invalid):
            try:
                rejected(binary, directory, a, candidate)
            except AssertionError as error:
                raise AssertionError(
                    f"invalid candidate {index} was not rejected: {candidate}"
                ) from error

        # Exercise the public numeric contract separately from rel-diff's
        # deliberate narrower u64 deserialization rule on ALL four fields.
        # Also reject on the left input, not only the right.
        verify_numeric_consumer_subset(
            binary, directory, input_validator, output_validator, a,
        )

        # Dense/escaped strings, inverse deltas, abstention and failed duplicates.
        verify_dense_escaped_metadata(
            binary, directory, input_validator, output_validator,
        )

        # End-to-end output budget: both controlled inputs stay below the
        # 16 MiB input cap, but their disjoint differences combine in stdout.
        # The accepted case sits 512 KiB below the 16 MiB report budget;
        # the rejected case crosses it without publishing partial stdout.
        near_length = (MAX_INPUT // 2) - (MAX_INPUT // 64)
        near_left = manifest("a", ["A" * near_length], [], [])
        near_right = manifest("b", ["B" * near_length], [], [])
        input_validator.validate(near_left)
        input_validator.validate(near_right)
        near_result, near_bytes = accepted(
            binary, directory, output_validator, near_left, near_right
        )
        assert 15 * 1024 * 1024 < len(near_bytes) < MAX_INPUT
        assert near_result["imports"]["added"] == near_right["imports"]
        assert near_result["imports"]["removed"] == near_left["imports"]
        del near_result, near_bytes, near_left, near_right

        large_left = manifest("a", ["A" * (8 * 1024 * 1024)], [], [])
        large_right = manifest("b", ["B" * (8 * 1024 * 1024)], [], [])
        assert len(json.dumps(large_left).encode()) < MAX_INPUT
        assert len(json.dumps(large_right).encode()) < MAX_INPUT
        too_much_output = execute(binary, directory, large_left, large_right)
        assert too_much_output.returncode != 0
        assert not too_much_output.stdout, "overflow published a partial report"
        assert b"output limit" in too_much_output.stderr

        right_path = directory / "right.json"
        left_path = directory / "left.json"
        right_path.write_text("{not json", encoding="utf-8")
        raw_bad = subprocess.run(
            [str(binary), str(left_path), str(right_path)],
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert raw_bad.returncode != 0 and not raw_bad.stdout

        right_path.write_bytes(b" " * (MAX_INPUT + 1))
        too_large = subprocess.run(
            [str(binary), str(left_path), str(right_path)],
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert too_large.returncode != 0 and not too_large.stdout
        assert b"16 MiB" in too_large.stderr

        if inspector is not None:
            inspect_real_fixture_pair(
                binary, inspector, directory, input_validator, output_validator
            )

    print("EX-02 independent manifest diff CLI oracle: PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--inspector", type=Path)
    args = parser.parse_args()
    verify(args.binary.resolve(), args.inspector.resolve() if args.inspector else None)
