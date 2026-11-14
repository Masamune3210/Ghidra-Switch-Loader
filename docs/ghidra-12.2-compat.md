# Ghidra 12.2 compatibility

## Integration

Integrated into `master` with the modern-kernel and Switch 2 NSO validation work. Extension version 1.6.7 distinguishes the integrated build from 1.6.6.

## Decisions

- Build for Ghidra 12.2 with JDK 25 and Gradle 9.1.
- Replace removed Gradle `Project.exec` with `providers.exec` for the Git build suffix.
- Retain `setup-ghidra@v2.3.0` from master and use Ghidra-generated extension metadata.
- CI runs standalone NSO/GOT regressions and packages the extension; release publishing is reserved for tag or manual builds.

## Verification

**Ghidra 12.2 CI passed** on `master` at `24af52a`: https://github.com/Masamune3210/Ghidra-Switch-Loader/actions/runs/43540969080. Java 25, both standalone NSO/GOT regression checks, Gradle build, extension packaging, and artifact upload all succeeded. Artifact: `SwitchLoader-1.6.7-24af52a-Ghidra_12.2`. Actual NSO/NRO imports and the new automatic GOT-detection behavior in Ghidra 12.2 remain unverified.
