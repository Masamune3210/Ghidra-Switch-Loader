# Ghidra 12.2 compatibility

## Integration

Integrated into `master` with the modern-kernel and Switch 2 NSO validation work. Extension version 1.6.7 distinguishes the integrated build from 1.6.6.

## Decisions

- Build for Ghidra 12.2 with JDK 25 and Gradle 9.1.
- Replace removed Gradle `Project.exec` with `providers.exec` for the Git build suffix.
- Retain `setup-ghidra@v2.3.0` from master and use Ghidra-generated extension metadata.
- CI runs standalone NSO/GOT regressions and packages the extension; release publishing is reserved for tag or manual builds.

## Verification

The latest 1.6.6 GOT detector passed standalone tests under Java 21. The complete integrated 12.2 build and Ghidra runtime NSO/NRO import have not yet been verified; check the new master CI run before claiming build compatibility.
