# Switch 2 NSO loader validation

> **Integration note (2026-11-13):** The `modern-kernel-loader` history is fully included in this branch. This branch's work was incorporated into `master` together with Ghidra 12.2 compatibility as extension **1.6.7**, at the user's request. Earlier instructions below to avoid merging describe the prior experimental state. The 1.6.6 standalone tests passed, but the new automatic GOT detector has **not** yet been verified through a fresh Ghidra import. The Ghidra 12.2 CI build and both standalone NSO/GOT tests passed: https://github.com/Masamune3210/Ghidra-Switch-Loader/actions/runs/43540969080. Reimport is still required before treating the GOT behavior as runtime-tested.

**Branch:** `note-working/switch2-nso-validation`  
**Base:** `note-working/modern-kernel-loader` at `986b3b3791066d0eb216b9c5b7b34bf4f130c1f1` (do not rewrite the modern-kernel work).  
**Status:** Fire Emblem `main` imports in Ghidra 12.1.3; NSO validation regressions previously passed. **Current extension version: 1.6.6.** `ValidateSwitchGot` now establishes an exactly contiguous, typed-relocation-backed GOT interval (not the original full gap). Automatic detection is implemented with fail-closed safeguards, but the 1.6.6 build and a fresh Ghidra import are not yet verified. Versions 1.6.4 and 1.6.5 were intermediate experiments, not final GOT fixes. Bump the patch number for each subsequent buildable change.

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

**Next action (updated):** The earlier GOT boundary guess is not established. Do not install `1.6.4` or reimport to test it. Instead run the read-only `ValidateSwitchGot.java` against the existing imported `main`; no new extension build is required for the script.


## 2026-11-13: GOT probe completed; pre-PLT detection in 1.6.4

- **User-provided `ProbeSwitchGot.java` output, Fire Emblem `main`:** image base `0x7100000000`, `.dynamic=0x710212BD48..0x710212BF07` (0x1C0), `.got.plt=0x7102137FE8..0x7102139A0F` (0x1A28). `DT_PLTGOT=0x2137FE8`, `DT_RELA=0x1A0D068`, `DT_RELASZ=0x58248`, `DT_JMPREL=0x1A652B0`, `DT_PLTRELSZ=0x4E30`, `DT_RELR=0x1A6A0E0`, `DT_RELRSZ=0x8098`. `.rela.dyn`: 15,043 entries (`1025=55`, `257=14,988`); `.rela.plt`: 834 entries (`1026=834`) with exactly one contiguous target range `0x2138000..0x2139A10` (end-exclusive, validating `.got.plt`). `.relr.dyn`: 218,170 targets, with dense runs including `0x212C968..0x212DD70` and `0x2135450..0x2137BA8`. `.rela.dyn` also has `0x212C540..0x212C598`. All addresses in the probe's relocation clusters are image-relative.
- **Determination:** The original `MOD0Adapter.findGot()` searched for `.got` immediately **after the end of `.got.plt`** (`0x2139A10`), while the observed layout has relocation-bearing data immediately following the end of `.dynamic`, **before** `.got.plt`. The **candidate ordinary GOT** is image-relative `0x212BF08..0x2137FE8` (exclusive), absolute `0x710212BF08..0x7102137FE8` (exclusive), length `0xC0E0` (6,172 8-byte slots). This is a derived section range awaiting a real reimport, not a claim that every slot was manually verified as a pointer.
- **Implemented** `src/main/java/adubbz/nx/loader/nxo/GotRegionDetector.java` as a pure-Java candidate detector. It requires both anchors within the NSO DATA region, valid pointer alignment, at least 16 relocation targets inside, and relocation evidence within 0x1000 of **both** bounds. No title-specific hardcoded offsets.
- **Implemented** `MOD0Adapter.findGot()` to try this relocation-backed pre-PLT range when a `.got.plt` block exists, **before** the original legacy heuristic (which is retained). Converted lookup membership to `HashSet`, avoiding expensive repeated linear searches over `DT_RELR` targets. Cached both success and failure so no more triple error log for absent GOT. `NXProgramBuilder` will create the `.got` block and pointer annotations using the detected range on *fresh* imports.
- **Added** `tools/GotRegionDetectorSmokeTest.java`: standalone JDK test with actual Fire Emblem anchor values and representative relocation runs, plus negative cases for invalid bounds, absent edge evidence, invalid pointer size, and unrelated relocations.
- **Extension version bumped** in `gradle.properties` from `1.6.3` to `1.6.4`. The ZIP name includes the numeric version and commit hash, and the extension metadata receives the version.
- **Verification status:** code/tests committed, **not built or run in Ghidra yet**. Only the user's *old* `1.6.3` `ProbeSwitchGot` results are verified. Keep previous successful ZBIC import and Pokopia negative extent results as distinct evidence. No merge to `modern-kernel-loader` or `master`.

### Superseded: do not install 1.6.4

The 1.6.4 detector classified the entire `0x212BF08..0x2137FE8` gap as `.got` using generic relocation density and section anchors. That inference is **unproven**: `R_AARCH64_ABS64` and `DT_RELR` also describe vtables and ordinary pointer arrays. That detector and its permissive synthetic test were deleted in 1.6.5. The original GOT heuristic remains with an O(1) relocation membership set and cached lookup outcome, so unresolved GOT locations produce one warning rather than three.

## 2026-11-13: evidence-based GOT verification in version 1.6.5

- **Original probe findings:** `R_AARCH64_GLOB_DAT` (1025): 55 targets; `R_AARCH64_ABS64` (257): 14,988 targets; `R_AARCH64_JUMP_SLOT` (1026): 834 targets in `.got.plt`; `DT_RELR`: 218,170 targets. Only the type-1025 relocation targets strongly indicate ordinary GOT slots. These counts don't locate all 55 without listing their destinations, and none proves the full `0xC0E0` gap is GOT.
- **New read-only script** `ghidra_scripts/ValidateSwitchGot.java` lists all `GLOB_DAT` targets and whether each is in the candidate range, pointer values, and mapped target sections. It also measures `GLOB_DAT`, `ABS64`, `JUMP_SLOT`, `RELR`, mapped/zero/unmapped values, and Ghidra-discovered code references in 4 KiB bins throughout the gap. Interpretation must respect incomplete code xrefs until auto-analysis finishes.
- **Changes:** Disabled the automatic pre-PLT `GotRegionDetector` candidate assignment in `MOD0Adapter.findGot()` and removed `GotRegionDetector.java` plus `GotRegionDetectorSmokeTest.java`. Bumped `gradle.properties` from `1.6.4` to **`1.6.5`**.
- **Verification:** `ValidateSwitchGot.java` **not yet run**; the new extension has **not been built or installed**. The user-supplied `ProbeSwitchGot.java` output is verified and the old Fire Emblem import succeeded. No confirmed ordinary `.got` region or pointer datatype redeclarations yet.
- **Decision rule:** Inspect all 55 `GLOB_DAT` addresses and associated dynamic symbols, GOT-style code references (ADRP/LDR or similar), and the content/relocation density transitions before defining a memory block. Dense `RELR` or `ABS64` by itself is inadequate evidence. If no defensible boundary emerges, leave `.got` unidentified rather than mark arbitrary data as pointers.

### Next action

With the existing Fire Emblem `main` database open in Ghidra's CodeBrowser, run **`ValidateSwitchGot.java`** via Script Manager and share its output. The script only reads the current program; no reimport and no new extension installation are required. If the current extension itself needs rebuilding, use version **1.6.5**, never 1.6.4.


## 2026-11-13: 1.6.6, contiguous typed relocation GOT boundary established

**New user-provided `ValidateSwitchGot.java` output (Fire Emblem `main`, image base `0x7100000000`):**

- Candidate `[0x212BF08, 0x2137FE8)`, but the **real contiguous relocated prefix ends earlier**.
- The `GLOB_DAT` set is **55/55 inside** the candidate, all import pointers resolve into Ghidra's artificial `EXTERNAL` block. `DT_RELR` contributes **5,989** relocated pointer slots inside. **Zero** ABS64 and JUMP_SLOT target locations inside. Those other relocation families occur outside this region.
- The first 11 probe bins contain exactly **512/512** relocated slots each. The 12th contains **404 RELR + 8 GLOB_DAT = 412** consecutive relocated slots followed by **100 zero** slots. The final bin adds **28 zero** slots. All nonzero relocated slots point to mapped memory, there are no absent or mixed-type slots in the prefix.
- Therefore **6,044 consecutive 8-byte relocated pointers** exist starting at `0x212BF08`, occupying **`0xBCE0` bytes**, and ending at **`0x2137BE8` exclusive**. The following **`0x400` bytes** are zero padding, then the independently established `.got.plt` begins at `0x2137FE8`.
- The strongest supported identification is **ordinary `.got`: image-relative `[0x212BF08, 0x2137BE8)`, absolute `[0x710212BF08, 0x7102137BE8)`**, 6,044 pointer slots. Exact absolute last byte `0x7102137BE7`; last pointer starts at `0x7102137BE0`. The earlier guessed end `0x2137FE8` incorrectly included `0x400` zero bytes, so do **not** propagate that old boundary.

**Source changes (Ghidra `note-working/switch2-nso-validation`):**

- Added pure-Java `GotRelocationEvidence.detect`. It requires an AArch64 `.dynamic`-end and an independently defined `.got.plt` start within DATA, exact 8-byte alignment, a single contiguous prefix with **only `R_AARCH64_GLOB_DAT` and expanded `DT_RELR`** per slot, at least one of each, at least 16 total slots, **no ABS64/other relocations or overlaps**, followed by no relocations and **all-zero original image padding**, with bounded gap and padding lengths. If any condition fails, it returns no candidate. The algorithm is per-binary, not hardcoded to this title or ExeFS grouping.
- `MOD0Adapter.findGot()` groups the existing `NXRelocation` objects by type (`R_AARCH64_GLOB_DAT=1025`, `ElfCompatibilityProvider.R_FAKE_RELR=-1`, everything else), probes this exact prefix when `.got.plt` exists, retains the historical heuristic as fallback, and caches the result. The existing `NXProgramBuilder` can create the precise `.got` memory block and pointer datatypes during a **new import**.
- Added `tools/GotRelocationEvidenceSmokeTest.java` with the **55 actual `GLOB_DAT` positions** from the user's output and 5,989 complementary RELR positions, checking the exact `0xBCE0` region and refusing ABS64 overlap, mid-region gaps, padding relocations/nonzero padding, out-of-DATA bounds, and an all-RELR range without import evidence.
- Bumped `gradle.properties` **1.6.5 -> 1.6.6**. The standalone Java detector and test **compiled under Java 21 and passed all 9 checks on 2026-11-13**, with file contents verified byte-for-byte against the GitHub blobs (`89107b25f1c367095e1f8829eff74ecf3a926fcf` and `1f79c7585cd13e56d19336426494047a10eb9c08`). **The full Ghidra extension/import has not been tested with these changes.** Previous successful NSO import validates compression/mapping only, not this updated `.got` behavior.

**Ghidra database metadata, directly applicable for the existing Fire Emblem `main` (confirmed by relocation type and slot coverage):**

```text
Address range: 0x710212BF08 - 0x7102137BE7
Label/block: .got
Type: pointer[6044]
Length: 0xBCE0 bytes
Next range: 0x7102137BE8 - 0x7102137FE7
Type: undefined1[1024] (zero padding; DO NOT add to .got)
Existing .got.plt: 0x7102137FE8 - 0x7102139A0F
```

**Next verification (one terminal command per line):**

```powershell
javac -d build/got-evidence src/main/java/adubbz/nx/loader/nxo/GotRelocationEvidence.java tools/GotRelocationEvidenceSmokeTest.java
java -cp build/got-evidence adubbz.nx.loader.nxo.GotRelocationEvidenceSmokeTest
.\gradlew.bat
```

Install **1.6.6**, restart Ghidra, reimport Fire Emblem `main` into a **new program** and check that the loader says `Located relocation-complete .got`, creates `.got` as **0xBCE0** bytes ending **before** the 0x400 zero padding, and still creates `.got.plt` without overlap. If either test or import fails, inspect the actual error and correct only the involved code. Do not merge this branch into `modern-kernel-loader` until verified.

