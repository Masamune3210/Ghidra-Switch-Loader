# Switch 2 NSO loader validation

**Branch:** `note-working/switch2-nso-validation`  
**Base:** `note-working/modern-kernel-loader` at `986b3b3791066d0eb216b9c5b7b34bf4f130c1f1` (do not rewrite the modern-kernel work).  
**Status:** plain-JDK tests passed; real Pokopia boundary error correctly rejected; Fire Emblem Fortune's Weave `main` **successfully imported in Ghidra 12.1.3** with ZBIC sections and relocations. `.got` detection remains unresolved. Current extension version **1.6.3**, and the patch number must increase with every future buildable source change.

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

**Verified by user (Ghidra 12.1.3, 2026-11-13):** Fire Emblem's actual `main` successfully imported into Ghidra. The application log shows dynamic blocks `.dynstr`, `.init_array`, `.rela.dyn`, `.relr.dyn`, `.rela.plt`, `.gnu.hash`; it processed JMPREL, DT_RELR and DT_RELA relocations, mapped `.text`, `.rodata`, `.data` and created `.bss` (0x7102177000..0x7102273D08). Ghidra created `/Games/Switch 2/Fire Emblem/main`. This is stronger evidence than the previous physical-boundary test and confirms successful ZBIC decompression and executable mapping. **Remaining:** `NSO0Adapter` emitted `Failed to find .got section.` three times, so `.got` pointer markup may be incomplete; this is nonfatal but should not be silently dismissed. Ghidra auto-analysis quality and a Switch 1 regression import remain unverified.

## Next

1. **Plain-JDK validator tests are complete.** Build the full extension (`.\gradlew.bat`) and import a known-valid Switch 1 NSO for regression coverage.
2. Import the Fire Emblem Fortune's Weave loose `base/exefs/main` with the newly built Ghidra extension. The independent boundary test already **passed**; verify actual section decompression, MOD0/ELF analysis and mappings, and report the first error if import fails.
3. Only then add targeted format/layout support. Keep all experimental changes on this branch until verified, and do not merge into `modern-kernel-loader` or the default branch without request.


## 2026-11-13: Fire Emblem raw NSO and GOT analysis, extension version policy

- Uploaded `main(5)` is **byte-identical** to previously supplied `main(4)` (SHA-256 `ee08f64d39f80c08c733e203be6f44c44265fdd69c7c824d562ab4f5d6d7d7d6`; file size `0xB7117A` = 11,997,562).
- `NSO0`, version 0, flags `0xBF` (ZBIC bit 7 set). Module name `app`, Build ID `adfd9b7066f1071c68219b001a90cc9260d6cb47` padded with zeros. Text: file `0x104`, compressed `0x970E7F`, expanded `0x1A0CF70`. Ro: file `0x970F83`, compressed `0x1B74A6`, expanded `0x542008`. Data: file `0xB28429`, compressed `0x48D51`, expanded `0x2262D0`. All three are literal ZBIC frames; all extents fit within EOF `0xB7117A`.
- User supplied Ghidra `application.log`: import was successful; sections, dynamic tables, relocations and BSS were created. The only reported loader error was **three instances** of `NSO0Adapter: Failed to find .got section.` These arise from `MOD0Adapter.findGot()`, whose heuristic only searches sequential relocation targets after the dynamic table or existing `.got.plt`. Do **not** invent a GOT interval; the log alone does not establish it.
- Added read-only `ghidra_scripts/ProbeSwitchGot.java` to report Ghidra memory sections, dynamic tags (including `DT_PLTGOT` and `DT_INIT_ARRAY`), relocation type counts and contiguous offset clusters from `.rela.dyn`, `.rela.plt` and `.relr.dyn`. Run with Fire Emblem's imported `main` active in CodeBrowser. Compare real offsets to the original heuristic before implementing GOT reconstruction. **Not yet executed.**
- **Version discipline requested by user:** Increment `gradle.properties` `version` patch number **every time buildable source/scripts are changed**, so both extension metadata and distribution ZIP name distinguish releases. Bumped `1.6.1 -> 1.6.2` to account for the existing NSO safety work, then `1.6.2 -> 1.6.3` for the GOT probe. Do not leave multiple source revisions using one numeric version. `build.gradle` already includes `project.version` and a Git hash in `archiveBaseName`.
- **Next:** With imported Fire Emblem `main` selected, run `ProbeSwitchGot.java` from the Script Manager and inspect the output. Derive exact GOT boundaries from anchored tags/relocations, then implement/test a minimal `MOD0Adapter` improvement, **bumping to `1.6.4`** in that same source change. Confirm the full Gradle build and a known-good Switch 1 NSO regression before promoting this branch.

## 2026-11-13: independent-file import invariant and ExeFS test samples

**User-corrected architecture:** `Ghidra-Switch-Loader` loads **one binary per invocation**, whether the user imports one file or batches multiple files. It must **never** assume that files belong to a particular ExeFS, auto-resolve companion modules, import linked files as a group, or require `main.npdm` alongside an NSO. The reference to a game ExeFS is provenance for independent per-file regression samples only.

**Real files provided, validated separately:** Fire Emblem Fortune's Weave `main` NSO0 uses ZBIC (flags `0xBF`), was imported successfully in Ghidra 12.1.3. Its `rtld`, `sdk`, `subsdk0`, `subsdk1`, `subsdk2` each declare LZ4 (flags `0x3F`), and all 15 independently decoded sections passed their original NSO header SHA-256 hashes, with every stored extent ending within its individual file. These are standalone positive fixtures for NSO LZ4 support, not a reason to change batching logic. Sizes: `rtld` 10,516; `sdk` 7,831,751; `subsdk0` 42,361,428; `subsdk1` 6,317,428; `subsdk2` 533,393 bytes. No group load behavior should be added.

**Separate metadata file:** User also provided `main.npdm` (1,828 bytes, SHA-256 `e61248bb2ab85a6274eb174b7d78d4188187b20e87b3b135cf0e1b28fbd22ff0`). It contains `META` at 0x0, extended ACID header at 0x380 (ACID block base 0x80 and 0x300-byte signature/key area), and ACI0 at 0x560. ACI Program ID `0x04007EF01F8AE000`, main thread priority 44, stack `0x100000`, system resource size `0x1800000`. ACI and ACID service-access descriptors each contain 46 entries. This can be parsed **independently** as NPDM data if such functionality is added; it is not a prerequisite to loading an NSO.

**Next action:** Wait for read-only `ProbeSwitchGot.java` output from imported Fire Emblem `main` to identify its actual GOT region before changing `MOD0Adapter.findGot()`. Keep each module's decompilation/address space distinct. Version remains `1.6.3`; this is a handoff-only update and does not produce different extension bytes.

