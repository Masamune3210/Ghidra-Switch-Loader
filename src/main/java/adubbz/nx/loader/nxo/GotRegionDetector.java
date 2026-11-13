package adubbz.nx.loader.nxo;

import java.util.Collection;

/**
 * Finds a candidate conventional GOT between the end of the dynamic table
 * and the beginning of an independently identified PLT GOT.
 *
 * Detection is per-module only. It never searches other files or uses
 * game-specific addresses. Requiring relocations near BOTH ends prevents
 * promoting arbitrary gaps between dynamic sections into a GOT.
 */
public final class GotRegionDetector
{
    private static final long EDGE_WINDOW = 0x1000L;
    private static final int MIN_RELOCATED_SLOTS = 16;

    private GotRegionDetector() {}

    /**
     * @return {start, exclusiveEnd} in image-relative bytes, or null.
     */
    public static long[] detectBeforePlt(long dynamicEnd, long gotPltStart,
                                         long dataStart, long dataSize,
                                         int pointerSize,
                                         Collection<Long> relocationTargets)
    {
        if ((pointerSize != 4 && pointerSize != 8) ||
            dynamicEnd < 0 || dataStart < 0 || dataSize <= 0 ||
            gotPltStart <= dynamicEnd || relocationTargets == null ||
            dataStart > Long.MAX_VALUE - dataSize ||
            dynamicEnd < dataStart || gotPltStart > dataStart + dataSize ||
            dynamicEnd % pointerSize != 0 ||
            gotPltStart % pointerSize != 0)
        {
            return null;
        }

        int relocated = 0;
        boolean nearStart = false;
        boolean nearEnd = false;

        for (long target : relocationTargets)
        {
            if (target < dynamicEnd || target >= gotPltStart ||
                target % pointerSize != 0)
            {
                continue;
            }

            relocated++;
            if (target - dynamicEnd < EDGE_WINDOW)
                nearStart = true;
            if (gotPltStart - target <= EDGE_WINDOW)
                nearEnd = true;
        }

        if (relocated < MIN_RELOCATED_SLOTS || !nearStart || !nearEnd)
            return null;

        return new long[] { dynamicEnd, gotPltStart };
    }
}
