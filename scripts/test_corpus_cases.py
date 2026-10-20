#!/usr/bin/env python3
"""Cross-platform tests for hashes, deterministic overlays and honest provenance."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from _internal.corpus_cases import (
    FIXTURE_NAMES, OVERLAY_SIZES, REDISTRIBUTION_STATUS, ROOT,
    load_verified_seeds, prepare_cases,
)


class CorpusCaseTests(unittest.TestCase):
    def test_tracked_fixture_hashes(self) -> None:
        seeds = load_verified_seeds(ROOT / "fixtures")
        self.assertEqual(tuple(n for n, _, _ in seeds), FIXTURE_NAMES)
        for name, data, digest in seeds:
            self.assertEqual(len(data), 2048)
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertTrue(name.endswith(".exe"))

    def test_fuzzer_seed_copies_match_pinned_synthetic_fixtures(self) -> None:
        """Fuzz corpus seeds cannot silently drift from the checked originals."""
        for name, seed, digest in load_verified_seeds(ROOT / "fixtures"):
            with self.subTest(name=name):
                fuzzer_copy = ROOT / "fuzz" / "corpus" / "pe_inspect" / name
                copied = fuzzer_copy.read_bytes()
                self.assertEqual(copied, seed)
                self.assertEqual(hashlib.sha256(copied).hexdigest(), digest)

    def test_rejects_tampered_reference_seed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp)
            fixtures = ROOT / "fixtures"
            (copied / "expected.json").write_bytes((fixtures / "expected.json").read_bytes())
            for name in FIXTURE_NAMES:
                (copied / name).write_bytes((fixtures / name).read_bytes())
            data = bytearray((copied / FIXTURE_NAMES[0]).read_bytes())
            data[-1] ^= 1
            (copied / FIXTURE_NAMES[0]).write_bytes(data)
            with self.assertRaisesRegex(ValueError, "hash/size mismatch"):
                load_verified_seeds(copied)

    def test_unique_cases_and_deterministic_overlay_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cases = prepare_cases(
                ROOT / "fixtures", Path(tmp), Path(tmp) / "unused",
                include_windows_executable=False,
            )
            self.assertEqual(len(cases), len(FIXTURE_NAMES) * (1 + len(OVERLAY_SIZES)))
            self.assertEqual(len({case.case_id for case in cases}), len(cases))
            for case in cases:
                self.assertEqual(case.report_fields()["redistribution_status"], REDISTRIBUTION_STATUS)
                seed = (ROOT / "fixtures" / case.source_fixture).read_bytes()
                with case.path.open("rb") as handle:
                    self.assertEqual(handle.read(len(seed)), seed)
                if case.kind == "synthetic-overlay":
                    size = int(case.case_id.split("-")[-1])
                    self.assertIn(size, OVERLAY_SIZES)
                    self.assertEqual(case.path.stat().st_size, size)
                    self.assertEqual(
                        case.path.read_bytes()[len(seed):], b"\x00" * (size - len(seed))
                    )
                else:
                    self.assertEqual(case.kind, "synthetic-fixture")

    def test_compiler_probe_requires_windows_mode_and_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            missing = folder / "missing.exe"
            with self.assertRaisesRegex(ValueError, "Windows corpus"):
                prepare_cases(
                    ROOT / "fixtures", folder, folder / "unused",
                    include_windows_executable=False, windows_msvc_probe=missing,
                )
            with self.assertRaises(FileNotFoundError):
                prepare_cases(
                    ROOT / "fixtures", folder, ROOT / "fixtures" / FIXTURE_NAMES[0],
                    include_windows_executable=True, windows_msvc_probe=missing,
                )

    def test_compiler_probe_provenance_never_implies_license(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            native = folder / "rel-inspect.exe"
            compiler_probe = folder / "msvc-probe.exe"
            native.write_bytes(b"local-test-native-placeholder")
            compiler_probe.write_bytes(b"MZnot-an-actual-PE-for-case-metadata-test")
            cases = prepare_cases(
                ROOT / "fixtures", folder, native,
                include_windows_executable=True, windows_msvc_probe=compiler_probe,
            )
            self.assertEqual(len(cases), 8)
            assert cases[-1].path == compiler_probe
            meta = cases[-1].report_fields()
            self.assertEqual(meta["case_id"], "msvc-x64-local-build")
            self.assertEqual(meta["kind"], "ci-built-msvc-x64-pe")
            self.assertEqual(meta["redistribution_status"], REDISTRIBUTION_STATUS)
            self.assertEqual(meta["source_fixture"], "fixtures/probes/msvc_probe.c")
            source = ROOT / meta["source_fixture"]
            self.assertEqual(meta["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())

    def test_clang_probe_requires_windows_mode_and_valid_toolchain_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            compiler_probe = folder / "rel-clang-cl-probe.exe"
            with self.assertRaisesRegex(ValueError, "Clang-cl probe requires"):
                prepare_cases(
                    ROOT / "fixtures", folder, folder / "unused",
                    include_windows_executable=False,
                    windows_clang_probe=compiler_probe,
                )
            compiler_probe.write_bytes(b"compiled-PE-placeholder")
            analyzer = folder / "rel-inspect.exe"
            analyzer.write_bytes(b"analyzer-placeholder")
            with self.assertRaises(FileNotFoundError):
                prepare_cases(
                    ROOT / "fixtures", folder, analyzer,
                    include_windows_executable=True,
                    windows_clang_probe=compiler_probe,
                )
            (folder / "clang-cl-version.txt").write_text(
                "unexpected toolchain\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "Clang version provenance"):
                prepare_cases(
                    ROOT / "fixtures", folder, analyzer,
                    include_windows_executable=True,
                    windows_clang_probe=compiler_probe,
                )

    def test_clang_probe_source_and_version_are_recorded_without_license_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            analyzer = folder / "rel-inspect.exe"
            clang_probe = folder / "rel-clang-cl-probe.exe"
            msvc_probe = folder / "rel-msvc-probe.exe"
            analyzer.write_bytes(b"analyzer-placeholder")
            clang_probe.write_bytes(b"clang-output-placeholder")
            msvc_probe.write_bytes(b"msvc-output-placeholder")
            (folder / "clang-cl-version.txt").write_text(
                "clang version 20.0.1 (test)\nTarget: x86_64-pc-windows-msvc\n",
                encoding="utf-8",
            )
            cases = prepare_cases(
                ROOT / "fixtures", folder, analyzer,
                include_windows_executable=True,
                windows_msvc_probe=msvc_probe,
                windows_clang_probe=clang_probe,
            )
            self.assertEqual(len(cases), 9)
            clang = cases[-1].report_fields()
            self.assertEqual(clang["case_id"], "clang-cl-x64-local-build")
            self.assertEqual(clang["kind"], "ci-built-clang-cl-x64-pe")
            self.assertEqual(clang["toolchain_version"], "clang version 20.0.1 (test)")
            self.assertEqual(clang["redistribution_status"], REDISTRIBUTION_STATUS)
            self.assertEqual(clang["source_fixture"], "fixtures/probes/msvc_probe.c")
            source = ROOT / clang["source_fixture"]
            self.assertEqual(clang["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertNotIn("toolchain_version", cases[-2].report_fields())

    def test_structured_probes_rejected_before_writing_overlays(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            missing = folder / "missing.exe"
            with self.assertRaisesRegex(ValueError, "Windows corpus mode"):
                prepare_cases(
                    ROOT / "fixtures", folder, folder / "unused",
                    include_windows_executable=False,
                    windows_msvc_structured=missing,
                )
            self.assertEqual(list(folder.iterdir()), [])
            with self.assertRaises(FileNotFoundError):
                prepare_cases(
                    ROOT / "fixtures", folder, ROOT / "fixtures" / FIXTURE_NAMES[0],
                    include_windows_executable=True,
                    windows_clang_structured=missing,
                )
            self.assertEqual(list(folder.iterdir()), [])

    def test_structured_cases_record_source_and_rc_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            native = folder / "rel-inspect.exe"
            msvc = folder / "rel-msvc-probe.exe"
            clang = folder / "rel-clang-cl-probe.exe"
            structured_msvc = folder / "rel-msvc-structured.exe"
            structured_clang = folder / "rel-clang-structured.exe"
            for path in (native, msvc, clang, structured_msvc, structured_clang):
                path.write_bytes(b"synthetic-path-only-test")
            (folder / "clang-cl-version.txt").write_text(
                "clang version 20.0.1 (test)\n", encoding="utf-8"
            )
            cases = prepare_cases(
                ROOT / "fixtures", folder, native,
                include_windows_executable=True,
                windows_msvc_probe=msvc, windows_clang_probe=clang,
                windows_msvc_structured=structured_msvc,
                windows_clang_structured=structured_clang,
            )
            self.assertEqual(len(cases), 11)
            self.assertEqual(len({case.case_id for case in cases}), 11)
            for case in cases[-2:]:
                metadata = case.report_fields()
                self.assertEqual(metadata["redistribution_status"], "not-established")
                source = ROOT / metadata["source_fixture"]
                asset = ROOT / metadata["resource_source"]
                self.assertEqual(
                    metadata["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest()
                )
                self.assertEqual(
                    metadata["resource_sha256"], hashlib.sha256(asset.read_bytes()).hexdigest()
                )
            self.assertEqual(cases[-2].case_id, "msvc-x64-structured")
            self.assertEqual(cases[-1].case_id, "clang-cl-x64-structured")
            self.assertEqual(cases[-1].toolchain_version, "clang version 20.0.1 (test)")

    def test_mingw_probe_checks_provenance_before_creating_overlays(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            probe = folder / "rel-mingw-x64-probe.exe"
            with self.assertRaises(FileNotFoundError):
                prepare_cases(
                    ROOT / "fixtures", folder, folder / "unused",
                    include_windows_executable=False, linux_mingw_probe=probe,
                )
            self.assertEqual(list(folder.iterdir()), [])
            probe.write_bytes(b"placeholder-compiled-pe")
            with self.assertRaises(FileNotFoundError):
                prepare_cases(
                    ROOT / "fixtures", folder, folder / "unused",
                    include_windows_executable=False, linux_mingw_probe=probe,
                )
            version = folder / "mingw-toolchain-version.txt"
            version.write_text("compiler unknown\nGNU ld synthetic\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "MinGW compiler/linker provenance"):
                prepare_cases(
                    ROOT / "fixtures", folder, folder / "unused",
                    include_windows_executable=False, linux_mingw_probe=probe,
                )
            self.assertFalse(any(folder.glob("*overlay*.exe")))

    def test_mingw_probe_is_a_distinct_source_verified_linux_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            probe = folder / "rel-mingw-x64-probe.exe"
            probe.write_bytes(b"placeholder-compiled-pe")
            (folder / "mingw-toolchain-version.txt").write_text(
                "x86_64-w64-mingw32-gcc (GCC) 13 test\n"
                "GNU ld (GNU Binutils) 2.42 test\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Linux corpus mode"):
                prepare_cases(
                    ROOT / "fixtures", folder, folder / "unused",
                    include_windows_executable=True, linux_mingw_probe=probe,
                )
            cases = prepare_cases(
                ROOT / "fixtures", folder, folder / "unused",
                include_windows_executable=False, linux_mingw_probe=probe,
            )
            self.assertEqual(len(cases), 7)
            self.assertEqual(len({case.case_id for case in cases}), 7)
            self.assertEqual(cases[-1].path, probe)
            meta = cases[-1].report_fields()
            self.assertEqual(meta["case_id"], "mingw-w64-x64-local-build")
            self.assertEqual(meta["redistribution_status"], "not-established")
            self.assertIn("GNU ld", meta["toolchain_version"])
            self.assertIn("gcc", meta["toolchain_version"])
            self.assertEqual(meta["source_fixture"], "fixtures/probes/msvc_probe.c")
            self.assertEqual(
                meta["source_sha256"],
                hashlib.sha256((ROOT / meta["source_fixture"]).read_bytes()).hexdigest(),
            )

    def test_native_build_case_does_not_claim_redistribution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            native = folder / "rel-inspect.exe"
            native.write_bytes(b"simulated-local-build-metadata")
            cases = prepare_cases(
                ROOT / "fixtures", folder, native, include_windows_executable=True
            )
            result = cases[-1].report_fields()
            self.assertEqual(result["kind"], "native-windows-rel-executable")
            self.assertEqual(result["provenance"], "locally-built-rel-cli")
            self.assertEqual(result["redistribution_status"], "not-established")
            self.assertIsNone(result["source_fixture"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
