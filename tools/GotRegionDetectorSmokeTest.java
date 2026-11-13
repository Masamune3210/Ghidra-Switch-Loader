package adubbz.nx.loader.nxo;

import java.util.ArrayList;
import java.util.List;

/**
 * Plain-JDK GOT-detection regression tests. No Ghidra installation needed.
 *
 * javac -d build/got-smoke src/main/java/adubbz/nx/loader/nxo/GotRegionDetector.java tools/GotRegionDetectorSmokeTest.java
 * java -cp build/got-smoke adubbz.nx.loader.nxo.GotRegionDetectorSmokeTest
 */
public final class GotRegionDetectorSmokeTest
{
    private GotRegionDetectorSmokeTest() {}

    private static void assertRange(long[] got, long from, long to, String description)
    {
        if (got == null || got[0] != from || got[1] != to)
            throw new AssertionError(description);
    }

    private static void assertMissing(long[] got, String description)
    {
        if (got != null)
            throw new AssertionError(description);
    }

    public static void main(String[] args)
    {
        // Anchors and representative relocation ranges from the actual
        // Fire Emblem Fortune's Weave main ProbeSwitchGot output.
        long dynamicEnd = 0x212BF08;
        long pltStart = 0x2137FE8;
        long dataStart = 0x1F50000;
        long dataSize = 0x2262D0;
        List<Long> targets = new ArrayList<>();

        // .rela.dyn cluster: 0x212C540..0x212C598
        for (long pos = 0x212C540; pos < 0x212C598; pos += 8)
            targets.add(pos);
        // Tail of .relr.dyn cluster: 0x2135450..0x2137BA8
        for (long pos = 0x2137A00; pos < 0x2137BA8; pos += 8)
            targets.add(pos);

        assertRange(GotRegionDetector.detectBeforePlt(dynamicEnd, pltStart,
            dataStart, dataSize, 8, targets), dynamicEnd, pltStart,
            "Fire Emblem: expected .got between .dynamic and .got.plt");

        assertMissing(GotRegionDetector.detectBeforePlt(dynamicEnd, pltStart,
            dataStart, dataSize, 8, targets.subList(0, 11)),
            "Must not infer GOT from targets only near one boundary");

        assertMissing(GotRegionDetector.detectBeforePlt(dynamicEnd, pltStart,
            dataStart, 0x100, 8, targets),
            "Must not infer GOT outside DATA");

        assertMissing(GotRegionDetector.detectBeforePlt(dynamicEnd, dynamicEnd,
            dataStart, dataSize, 8, targets),
            "Must reject empty/inverted GOT span");

        assertMissing(GotRegionDetector.detectBeforePlt(dynamicEnd, pltStart,
            dataStart, dataSize, 3, targets),
            "Must reject unsupported pointer size");

        List<Long> unrelated = new ArrayList<>();
        for (long pos = 0x1F50000; pos < 0x1F51000; pos += 8)
            unrelated.add(pos);
        assertMissing(GotRegionDetector.detectBeforePlt(dynamicEnd, pltStart,
            dataStart, dataSize, 8, unrelated),
            "Relocations outside candidate cannot establish GOT");

        System.out.println("GOT region detection: PASS (6 checks)");
        System.out.printf("Fire Emblem .got candidate: 0x%X..0x%X (0x%X bytes)%n",
            dynamicEnd, pltStart, pltStart - dynamicEnd);
    }
}
