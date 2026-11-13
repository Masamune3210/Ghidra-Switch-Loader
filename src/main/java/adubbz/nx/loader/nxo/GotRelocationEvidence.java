package adubbz.nx.loader.nxo;

import java.util.Set;
import java.util.function.LongPredicate;

/**
 * Infer only a fully relocation-covered, contiguous GOT prefix following
 * .dynamic, bounded by independently identified .got.plt.
 *
 * AArch64 GLOB_DAT and RELR are the only admitted slot types; ABS64, holes,
 * nonzero padding, overlapping relocations, and ambiguous boundaries reject
 * the candidate. This does NOT infer a GOT from generic relocation density.
 */
public final class GotRelocationEvidence
{
    private static final long MAX_SPAN = 0x100000L;
    private static final long MAX_PADDING = 0x1000L;
    private static final int MIN_SLOTS = 16;

    private GotRelocationEvidence() {}

    /**
     * @param dynamicEnd image-relative address immediately after .dynamic
     * @param pltStart image-relative address of .got.plt (DT_PLTGOT)
     * @param dataStart image-relative DATA segment start
     * @param dataSize DATA segment length, including GOT
     * @param globDat R_AARCH64_GLOB_DAT relocation targets
     * @param relr expanded DT_RELR relocation targets
     * @param otherTargets all other relocation types, e.g. ABS64
     * @param isZeroPadding reads the original (unrelocated) image at each slot
     * @return {inclusive start, exclusive end} or null if not proven
     */
    public static long[] detect(long dynamicEnd, long pltStart,
                                long dataStart, long dataSize,
                                Set<Long> globDat, Set<Long> relr,
                                Set<Long> otherTargets, LongPredicate isZeroPadding)
    {
        if (dynamicEnd < 0 || pltStart <= dynamicEnd || dataStart < 0 ||
            dataSize <= 0 || dataSize > Long.MAX_VALUE - dataStart ||
            dynamicEnd < dataStart || pltStart > dataStart + dataSize ||
            pltStart - dynamicEnd > MAX_SPAN ||
            (dynamicEnd & 7L) != 0 || (pltStart & 7L) != 0 ||
            globDat == null || relr == null || otherTargets == null ||
            isZeroPadding == null)
            return null;

        long end = dynamicEnd;
        int count = 0;
        int importCount = 0;
        int relativeCount = 0;
        boolean padding = false;

        for (long slot = dynamicEnd; slot < pltStart; slot += 8)
        {
            boolean imported = globDat.contains(slot);
            boolean relative = relr.contains(slot);
            if (otherTargets.contains(slot) || (imported && relative))
                return null;

            if (!padding && (imported || relative))
            {
                end = slot + 8;
                count++;
                if (imported) importCount++;
                if (relative) relativeCount++;
                continue;
            }

            // Once the first missing relocation is encountered, everything
            // until .got.plt must be true, unrelocated, zero-filled padding.
            padding = true;
            if (imported || relative || !isZeroPadding.test(slot))
                return null;
        }

        long tail = pltStart - end;
        if (count < MIN_SLOTS || importCount == 0 || relativeCount == 0 ||
            tail > MAX_PADDING)
            return null;

        return new long[] { dynamicEnd, end };
    }
}
