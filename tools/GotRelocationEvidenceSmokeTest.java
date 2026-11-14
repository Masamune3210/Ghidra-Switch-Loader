package adubbz.nx.loader.nxo;

import java.util.HashSet;
import java.util.Set;

/**
 * Standalone JDK tests for typed relocation evidence and exact GOT end.
 * javac -d build/got-evidence src/main/java/adubbz/nx/loader/nxo/GotRelocationEvidence.java tools/GotRelocationEvidenceSmokeTest.java
 * java -cp build/got-evidence adubbz.nx.loader.nxo.GotRelocationEvidenceSmokeTest
 */
public final class GotRelocationEvidenceSmokeTest
{
    private GotRelocationEvidenceSmokeTest() {}

    private static void require(boolean ok, String name)
    {
        if (!ok) throw new AssertionError(name);
    }

    public static void main(String[] args)
    {
        final long start = 0x212BF08L;
        final long gotEnd = 0x2137BE8L;
        final long plt = 0x2137FE8L;
        final long dataStart = 0x1F50000L;
        final long dataSize = 0x2262D0L;

        Set<Long> imports = new HashSet<>();
        Set<Long> relative = new HashSet<>();
        Set<Long> other = new HashSet<>();

        // 6044 continuous relocated slots: 55 GLOB_DAT and 5989 RELR.
        // All 55 exact GLOB_DAT destinations were recorded by the user's
        // ValidateSwitchGot probe. The other slots are all RELR.
        long[] globOffsets = {
            0x212C060, 0x212C148, 0x212C188, 0x212C190,
            0x212C298, 0x212C2A0, 0x212C2A8, 0x212C2B0,
            0x212C2F0, 0x212C2F8, 0x212C308, 0x212C3D8,
            0x212C540, 0x212C548, 0x212C550, 0x212C558,
            0x212C560, 0x212C568, 0x212C570, 0x212C578,
            0x212C580, 0x212C588, 0x212C590, 0x212C728,
            0x212C958, 0x212C960, 0x212DD70, 0x212E288,
            0x212E350, 0x212E8B0, 0x212EA28, 0x212EA30,
            0x212EA38, 0x212EAD8, 0x212EAE0, 0x212EAE8,
            0x212EAF0, 0x212F3B0, 0x212F3B8, 0x212FCD8,
            0x2132158, 0x2134020, 0x2134028, 0x2134030,
            0x2134038, 0x2134E40, 0x2135448, 0x2137BA8,
            0x2137BB0, 0x2137BB8, 0x2137BC0, 0x2137BC8,
            0x2137BD0, 0x2137BD8, 0x2137BE0
        };
        for (long offset : globOffsets) imports.add(offset);
        for (long p = start; p < gotEnd; p += 8)
            if (!imports.contains(p)) relative.add(p);

        require(imports.size() == 55, "55 GLOB_DAT targets");
        require(relative.size() == 5989, "5989 RELR targets");

        long[] got = GotRelocationEvidence.detect(
            start, plt, dataStart, dataSize,
            imports, relative, other, ignored -> true);
        require(got != null && got[0] == start && got[1] == gotEnd,
            "exact GOT must exclude 0x400-byte padding");
        require(gotEnd - start == 0xBCE0, "expected GOT length");

        // Introducing any ABS64 relocation within the interval invalidates
        // the inference rather than silently annotating non-GOT data.
        other.add(start + 0x80);
        require(GotRelocationEvidence.detect(
            start, plt, dataStart, dataSize,
            imports, relative, other, ignored -> true) == null,
            "ABS64 inside candidate should reject");
        other.clear();

        relative.remove(start + 0x80);
        require(GotRelocationEvidence.detect(
            start, plt, dataStart, dataSize,
            imports, relative, other, ignored -> true) == null,
            "hole followed by relocation should reject");
        relative.add(start + 0x80);

        relative.add(gotEnd + 8);
        require(GotRelocationEvidence.detect(
            start, plt, dataStart, dataSize,
            imports, relative, other, ignored -> true) == null,
            "relocation in padding should reject");
        relative.remove(gotEnd + 8);

        require(GotRelocationEvidence.detect(
            start, plt, dataStart, dataSize,
            imports, relative, other, p -> p != gotEnd) == null,
            "nonzero padding should reject");

        require(GotRelocationEvidence.detect(
            start, plt, dataStart, 0x100,
            imports, relative, other, ignored -> true) == null,
            "candidate beyond DATA should reject");

        Set<Long> noImports = new HashSet<>();
        Set<Long> relrOnly = new HashSet<>(relative);
        relrOnly.addAll(imports);
        require(GotRelocationEvidence.detect(
            start, plt, dataStart, dataSize,
            noImports, relrOnly, other, ignored -> true) == null,
            "no GLOB_DAT is insufficient to infer type-specific GOT");

        require(GotRelocationEvidence.detect(
            start, plt, dataStart, dataSize,
            imports, relative, other, ignored -> true) != null,
            "positive case still passes");

        System.out.println("Typed GOT relocation validation: PASS (9 checks)");
        System.out.printf("Fire Emblem GOT: relative 0x%X..0x%X, 0x%X bytes; padding 0x%X%n",
            start, gotEnd, gotEnd - start, plt - gotEnd);
    }
}
