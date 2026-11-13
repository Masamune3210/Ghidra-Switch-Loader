package adubbz.nx.loader.nso0;

import java.io.IOException;

/**
 * Validates NSO0's three independently stored sections before allocating an
 * image or invoking an LZ4/ZBIC decoder. Kept independent of Ghidra APIs so
 * the boundary checks can be exercised with a plain JDK.
 */
public final class NSO0LayoutValidator
{
    private static final long NSO_HEADER_SIZE = 0x100L;
    private static final String[] SECTION_NAMES = { "TEXT", "RODATA", "DATA" };

    private NSO0LayoutValidator() {}

    /**
     * @return the minimum image allocation size for the declared memory ranges.
     */
    public static int validate(long fileLength, long[] fileOffsets, long[] storedSizes,
                               long[] memoryOffsets, long[] memorySizes) throws IOException
    {
        if (fileLength < NSO_HEADER_SIZE)
            throw new IOException("NSO0 header truncated: file size " + fileLength);

        if (fileOffsets.length != 3 || storedSizes.length != 3 ||
            memoryOffsets.length != 3 || memorySizes.length != 3)
        {
            throw new IllegalArgumentException("NSO0 requires three section records");
        }

        long imageLength = 0;

        for (int index = 0; index < 3; index++)
        {
            long fileOffset = fileOffsets[index];
            long storedSize = storedSizes[index];
            long memoryOffset = memoryOffsets[index];
            long memorySize = memorySizes[index];
            String name = SECTION_NAMES[index];

            if (memoryOffset < 0 || memorySize < 0 ||
                memoryOffset > Integer.MAX_VALUE ||
                memorySize > Integer.MAX_VALUE - memoryOffset)
            {
                throw new IOException(String.format(
                    "NSO0 %s memory range exceeds Java array address space: offset=0x%X size=0x%X",
                    name, memoryOffset, memorySize));
            }

            imageLength = Math.max(imageLength, memoryOffset + memorySize);

            if (memorySize == 0)
                continue;

            // Check via subtraction to avoid integer overflow in offset + size.
            if (storedSize <= 0 || fileOffset < NSO_HEADER_SIZE ||
                fileOffset > fileLength || storedSize > fileLength - fileOffset)
            {
                throw new IOException(String.format(
                    "NSO0 %s stored extent invalid: fileOffset=0x%X storedSize=0x%X " +
                    "end=0x%X fileSize=0x%X",
                    name, fileOffset, storedSize, fileOffset + storedSize, fileLength));
            }
        }

        return Math.toIntExact(imageLength);
    }
}
