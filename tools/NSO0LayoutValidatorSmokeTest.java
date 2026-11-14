package adubbz.nx.loader.nso0;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Plain-JDK smoke checks for NSO0LayoutValidator.
 *
 * Compile:
 * javac -d build/nso-smoke src/main/java/adubbz/nx/loader/nso0/NSO0LayoutValidator.java tools/NSO0LayoutValidatorSmokeTest.java
 * Run:
 * java -cp build/nso-smoke adubbz.nx.loader.nso0.NSO0LayoutValidatorSmokeTest [main.nso]
 */
public final class NSO0LayoutValidatorSmokeTest
{
    private NSO0LayoutValidatorSmokeTest() {}

    private static void require(boolean condition, String message)
    {
        if (!condition)
            throw new AssertionError(message);
    }

    private static void rejects(long length, long[] fileOffsets, long[] storedSizes,
                                long[] memoryOffsets, long[] memorySizes, String expected)
    {
        try
        {
            NSO0LayoutValidator.validate(length, fileOffsets, storedSizes, memoryOffsets, memorySizes);
            throw new AssertionError("Expected rejection for " + expected);
        }
        catch (IOException e)
        {
            require(e.getMessage().contains(expected),
                "Expected " + expected + " in: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception
    {
        long[] offsets = { 0x100, 0x110, 0x120 };
        long[] lengths = { 0x10, 0x10, 0x10 };
        long[] memory = { 0, 0x1000, 0x2000 };
        long[] sizes = { 0x10, 0x10, 0x10 };

        int valid = NSO0LayoutValidator.validate(0x130, offsets, lengths, memory, sizes);
        require(valid == 0x2010, "A segment ending at EOF must be valid");
        rejects(0x12F, offsets, lengths, memory, sizes, "DATA stored extent");
        rejects(0x130, offsets, new long[] { 0x10, 0x31, 0x10 },
                memory, sizes, "RODATA stored extent");
        rejects(0x130, offsets, lengths,
                new long[] { 0, 0x1000, Integer.MAX_VALUE },
                new long[] { 0x10, 0x10, 2 }, "DATA memory range");

        System.out.println("Synthetic NSO0 layout validation: PASS");

        if (args.length == 1)
        {
            Path path = Path.of(args[0]);
            long fileLength = Files.size(path);
            byte[] head;
            try (var input = Files.newInputStream(path))
            {
                head = input.readNBytes(0x100);
            }
            require(head.length == 0x100 && head[0] == 'N' && head[1] == 'S' &&
                head[2] == 'O' && head[3] == '0', "Input must be an NSO0");
            ByteBuffer buffer = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN);
            long flags = Integer.toUnsignedLong(buffer.getInt(0xC));
            long[] storedOffsets = new long[3];
            long[] storedSizes = new long[3];
            long[] memoryOffsets = new long[3];
            long[] memorySizes = new long[3];

            for (int i = 0; i < 3; i++)
            {
                storedOffsets[i] = Integer.toUnsignedLong(buffer.getInt(0x10 + 0x10 * i));
                memoryOffsets[i] = Integer.toUnsignedLong(buffer.getInt(0x14 + 0x10 * i));
                memorySizes[i] = Integer.toUnsignedLong(buffer.getInt(0x18 + 0x10 * i));
                storedSizes[i] = ((flags & (1L << i)) != 0)
                    ? Integer.toUnsignedLong(buffer.getInt(0x60 + 4 * i))
                    : memorySizes[i];
            }

            try
            {
                NSO0LayoutValidator.validate(
                    fileLength, storedOffsets, storedSizes, memoryOffsets, memorySizes);
                System.out.println("Real NSO0 section bounds: PASS");
            }
            catch (IOException e)
            {
                System.out.println("Real NSO0 section bounds: REJECTED: " + e.getMessage());
            }
        }
    }
}
