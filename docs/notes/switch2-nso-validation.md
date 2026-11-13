# Switch 2 NSO loader validation

**Branch:** `note-working/switch2-nso-validation`  
**Base:** `note-working/modern-kernel-loader` at `986b3b3791066d0eb216b9c5b7b34bf4f130c1f1` (do not rewrite the modern-kernel work).  
**Status:** plain-JDK synthetic validation and two real-file boundary checks **passed on Windows** (Pokopia correctly rejected; Fire Emblem Fortune's Weave `main` correctly accepted); full Ghidra extension build/import **not yet verified**.

## Why this branch exists

Switch 2 application dumps use the familiar `NSO0` loader entry point. This fork already supported whole-file ZBIC, bit-7 ZBIC NSO segments and modern (17+) kernel discovery. Its normal NSO path, however, read blindly from header-declared section offsets and used `LZ4FastDecompressor` with no physical extent checks or decoded-size verification. Truncated or differently-encoded files could fail with unhelpful exceptions or partially initialized adapters.

A real, already-uploaded NUP-extracted `pokopia.main.nso` provided a specific negative test case:

- `NSO0`, flags `0x0000003F`, physical length `0x1C0ABC8`.
- DATA stored extent `0x1B51843 + 0xB9759 = 0x1C0AF9C`, exceeding physical EOF by `0x3D4` / 980 bytes.
- Text and Ro independently fail LZ4 and the file's NSO section hashes do not match. That discrepancy predates this loader. Do not silently reinterpret the whole executable as a single LZ4 block or disable section integrity checks.

## Changes

- `src/main/java/adubbz/nx/loader/nso0/NSO0LayoutValidator.java`: checks header length, nonempty stored-section extents, and memory image array bounds using overflow-safe arithmetic. Emits a descriptive error with section name, stored offset, size, end and file length. Plain JDK code, no Ghidra dependency.
- `NSO0Adapter.java`: validates all three sections **before allocating/decompressing**, uses `LZ4SafeDecompressor` instead of the fast decoder, checks the exact decoded byte count and reports malformed LZ4 blocks through `IOException`. Retains existing ZBIC frame handling. A zero-length section yields an empty array without invoking a decoder.
- `NSO0Header.java` / `NSO0SectionHeader.java`: stop swallowing short-read errors and restore the caller's BinaryReader index in a finally block.
- `SwitchLoader.java`: malformed/unsupported NSO adapter errors no longer escape the import-format probe as an unchecked exception; errors on actual import become an `IOException` with useful context.
- `tools/NSO0LayoutValidatorSmokeTest.java`: plain-JDK synthetic extent tests and optional validation of a supplied NSO file, including Pokopia.

This is **defensive compatibility work**, not full Switch 2 support. The Fire Emblem Fortune's Weave `main` shown in Ghidra's import dialog has not been supplied as bytes, so successful decoding of that particular executable is **not established**.

## Verification

Run from the Ghidra loader repository root (one command per line):

```powershell
javac -d build/nso-smoke src/main/java/adubbz/nx/loader/nso0/NSO0LayoutValidator.java tools/NSO0LayoutValidatorSmokeTest.java
java -cp build/nso-smoke adubbz.nx.loader.nso0.NSO0LayoutValidatorSmokeTest
java -cp build/nso-smoke adubbz.nx.loader.nso0.NSO0LayoutValidatorSmokeTest "G:\Users\Johnny\Downloads\yes\pokopia.main.nso"
.\gradlew.bat
```

The synthetic test should print `Synthetic NSO0 layout validation: PASS`. The Pokopia test should print a **DATA stored extent** rejection and `fileSize=0x1C0ABC8`; a rejection is the correct result for that NSO. Building the full extension requires `GHIDRA_INSTALL_DIR`, the Ghidra SDK and the repository's Gradle dependencies.

**Verified by user on Windows (2026-11-13):** `javac -d build/nso-smoke src/main/java/adubbz/nx/loader/nso0/NSO0LayoutValidator.java tools/NSO0LayoutValidatorSmokeTest.java` completed successfully. Running `java -cp build/nso-smoke adubbz.nx.loader.nso0.NSO0LayoutValidatorSmokeTest "G:\Users\Johnny\Downloads\yes\pokopia.main.nso"` printed `Synthetic NSO0 layout validation: PASS` and `Real NSO0 section bounds: REJECTED: NSO0 DATA stored extent invalid: fileOffset=0x1B51843 storedSize=0xB9759 end=0x1C0AF9C fileSize=0x1C0ABC8`. Both are expected: the real file is a deliberate negative test.

**Further user verification (2026-11-13):** `java -cp build/nso-smoke adubbz.nx.loader.nso0.NSO0LayoutValidatorSmokeTest "G:\Users\Johnny\Downloads\yes\Fire Emblem Fortune's Weave\base\exefs\main"` produced `Synthetic NSO0 layout validation: PASS` and `Real NSO0 section bounds: PASS`. This proves that the **physical NSO section extent checks** accept the Fire Emblem loose `main`, in contrast with the Pokopia negative test. No compressed sections were decoded by this smoke test.

**Not yet verified:** full Gradle/Ghidra extension build or actual Ghidra import/decompression of Fire Emblem; valid Switch 1 NSO regression compatibility.

## Next

1. **Plain-JDK validator tests are complete.** Build the full extension (`.\gradlew.bat`) and import a known-valid Switch 1 NSO for regression coverage.
2. Import the Fire Emblem Fortune's Weave loose `base/exefs/main` with the newly built Ghidra extension. The independent boundary test already **passed**; verify actual section decompression, MOD0/ELF analysis and mappings, and report the first error if import fails.
3. Only then add targeted format/layout support. Keep all experimental changes on this branch until verified, and do not merge into `modern-kernel-loader` or the default branch without request.
