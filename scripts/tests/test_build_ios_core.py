"""Keep Rust linker symbols intact when packaging the Apple core slices."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "build-ios-core.sh"
TARGETS = (
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "aarch64-apple-darwin",
    "aarch64-apple-watchos",
    "aarch64-apple-watchos-sim",
)


@unittest.skipUnless(sys.platform == "darwin", "requires Apple's Mach-O tools")
class CoreArchivePackagingTests(unittest.TestCase):
    def test_every_slice_preserves_distinct_llvm_symbols(self):
        with tempfile.TemporaryDirectory(prefix="apassy-core-packaging-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copyfile(SCRIPT, root / "scripts/build-ios-core.sh")
            (root / "ios/ApassyCore/include").mkdir(parents=True)
            tools = root / "tools"
            tools.mkdir()

            # LLVM gives optimized private functions distinct suffixes. Apple strip
            # removes these even with just -S, coalescing different implementations.
            # Use real Mach-O objects, not a text fixture or a mocked strip command.
            objects = []
            for index in (111, 222):
                source = root / f"function-{index}.c"
                source.write_text(
                    '__attribute__((weak, visibility("hidden"))) '
                    f'int function(void) __asm__("apassy_packaging.llvm.{index}");\n'
                    f'int function(void) {{ return {index}; }}\n'
                )
                obj = source.with_suffix(".o")
                subprocess.run(["xcrun", "clang", "-c", str(source), "-o", str(obj)], check=True)
                objects.append(str(obj))
            archive = root / "fixture.a"
            subprocess.run(["xcrun", "libtool", "-static", "-o", str(archive), *objects], check=True)
            original = archive.read_bytes()
            symbols = subprocess.check_output(["xcrun", "nm", "-g", "-U", "-j", str(archive)], text=True)
            self.assertIn("apassy_packaging.llvm.111", symbols)
            self.assertIn("apassy_packaging.llvm.222", symbols)
            for target in TARGETS:
                release = root / "target" / target / "release"
                release.mkdir(parents=True)
                shutil.copyfile(archive, release / "libapassy_core.a")
            examples = root / "target/aarch64-apple-darwin/release/examples"
            examples.mkdir()
            (examples / "questions_macs").write_text("synthetic helper")

            # Only Cargo, rustup, and XCFramework assembly are stubbed: the test
            # exercises the actual script's handling of a real linker input.
            commands = {
                "cargo": '#!/bin/sh\nif [ "$1" = metadata ]; then printf \'{"target_directory":"%s/target"}\\n\' "$APASSY_PACKAGING_ROOT"; fi\n',
                "rustup": "#!/bin/sh\nprintf '%s\\n' " + " ".join(TARGETS) + "\n",
                "xcodebuild": "#!/bin/sh\nexit 0\n",
            }
            for name, text in commands.items():
                executable = tools / name
                executable.write_text(text)
                executable.chmod(0o755)
            env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}", APASSY_PACKAGING_ROOT=str(root))
            subprocess.run(["bash", str(root / "scripts/build-ios-core.sh")], env=env, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            for target in TARGETS:
                with self.subTest(target=target):
                    packaged = root / "ios/ApassyCore/build" / target / "libapassy_core.a"
                    packaged_symbols = subprocess.check_output(
                        ["xcrun", "nm", "-g", "-U", "-j", str(packaged)], text=True)
                    self.assertEqual(packaged_symbols, symbols)
                    self.assertEqual(packaged.read_bytes(), original,
                                     "Packaging must not rewrite Rust's private linker symbols")
            self.assertEqual((root / "ios/ApassyCore/build/questions-macs").read_text(), "synthetic helper")

            client = root / "client.c"
            client.write_text(
                'int first(void) __asm__("apassy_packaging.llvm.111");\n'
                'int second(void) __asm__("apassy_packaging.llvm.222");\n'
                'int main(void) { return first() != 111 || second() != 222; }\n'
            )
            executable = root / "client"
            subprocess.run(["xcrun", "clang", str(client), str(root / "ios/ApassyCore/build" /
                            "aarch64-apple-darwin/libapassy_core.a"), "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
