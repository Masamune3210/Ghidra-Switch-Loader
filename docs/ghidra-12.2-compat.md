# Ghidra 12.2 compatibility branch

Reason: move the Switch loader extension build to Ghidra 12.2 without changing the loader's runtime behavior.

## Decisions
- Retain extension version 1.6.1 and Ghidra-generated extension metadata; the target Ghidra release is encoded in the built archive name.
- Use JDK 25 and Gradle 9.1 for Ghidra 12.2.
- Replace removed Gradle Project.exec with providers.exec for the Git build suffix.
- Only publish releases on tags or manual dispatch; branch pushes and pull requests build artifacts without publishing releases.

## State
- Build scripts and CI workflow updated for 12.2.
- No Ghidra 12.2 compile, import, or runtime test has been performed here.

## Next step
Check the Ghidra 12.2 CI build on this branch, inspect compiler errors if any, then test NRO/NSO loading and automatic analysis inside a 12.2 installation.
