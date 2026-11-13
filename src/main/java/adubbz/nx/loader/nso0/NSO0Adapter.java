/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nso0;

import adubbz.nx.util.ZbicUtil;
import adubbz.nx.common.ZbicException;

import java.io.IOException;

import adubbz.nx.loader.nxo.MOD0Adapter;
import adubbz.nx.loader.nxo.NXOSection;
import adubbz.nx.loader.nxo.NXOSectionType;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.listing.Program;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4Exception;
import net.jpountz.lz4.LZ4SafeDecompressor;

public class NSO0Adapter extends MOD0Adapter
{
    protected NSO0Header nso0;
    
    protected ByteProvider memoryProvider;
    protected NXOSection[] sections;
    
    public NSO0Adapter(Program program, ByteProvider fileProvider)
    {
        super(program, fileProvider);
        
        try
        {
            this.read();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Cannot read NSO0: " + e.getMessage(), e);
        }
    }
    
    private void read() throws IOException
    {
        this.nso0 = new NSO0Header(this.fileReader, 0x0);

        LZ4Factory factory = LZ4Factory.fastestInstance();
        LZ4SafeDecompressor lz4 = factory.safeDecompressor();

        NSO0SectionHeader textHeader  = this.nso0.getSectionHeader(NXOSectionType.TEXT);
        NSO0SectionHeader rodataHeader = this.nso0.getSectionHeader(NXOSectionType.RODATA);
        NSO0SectionHeader dataHeader  = this.nso0.getSectionHeader(NXOSectionType.DATA);

        long textOffset  = textHeader.getMemoryOffset();
        long rodataOffset = rodataHeader.getMemoryOffset();
        long dataOffset  = dataHeader.getMemoryOffset();
        long textSize    = textHeader.getDecompressedSize();
        long rodataSize  = rodataHeader.getDecompressedSize();
        long dataSize    = dataHeader.getDecompressedSize();

        long[] fileOffsets = new long[3];
        long[] storedSizes = new long[3];
        long[] memoryOffsets = { textOffset, rodataOffset, dataOffset };
        long[] memorySizes = { textSize, rodataSize, dataSize };
        for (NXOSectionType type : new NXOSectionType[] {
            NXOSectionType.TEXT, NXOSectionType.RODATA, NXOSectionType.DATA })
        {
            int index = type.ordinal();
            fileOffsets[index] = this.nso0.getSectionFileOffset(type);
            storedSizes[index] = this.nso0.isSectionCompressed(type)
                ? this.nso0.getCompressedSectionSize(type)
                : memorySizes[index];
        }

        // A 0x3F NSO is not necessarily valid LZ4 just because its flags
        // request LZ4. Verify physical extents before reading or decoding.
        int imageLength = NSO0LayoutValidator.validate(
            this.fileProvider.length(), fileOffsets, storedSizes, memoryOffsets, memorySizes);
        byte[] full = new byte[imageLength];

        boolean isZbic = this.nso0.isZbic();

        // TEXT
        byte[] decompressedText = decompressSection(
            NXOSectionType.TEXT, textSize, isZbic, lz4);
        System.arraycopy(decompressedText, 0, full,
            Math.toIntExact(textOffset), Math.toIntExact(textSize));

        // RODATA
        byte[] decompressedRodata = decompressSection(
            NXOSectionType.RODATA, rodataSize, isZbic, lz4);
        System.arraycopy(decompressedRodata, 0, full,
            Math.toIntExact(rodataOffset), Math.toIntExact(rodataSize));

        // DATA
        byte[] decompressedData = decompressSection(
            NXOSectionType.DATA, dataSize, isZbic, lz4);
        System.arraycopy(decompressedData, 0, full,
            Math.toIntExact(dataOffset), Math.toIntExact(dataSize));

        this.memoryProvider = new ByteArrayProvider(full);

        this.sections = new NXOSection[3];
        this.sections[NXOSectionType.TEXT.ordinal()]   = new NXOSection(NXOSectionType.TEXT,   textOffset,  textSize);
        this.sections[NXOSectionType.RODATA.ordinal()] = new NXOSection(NXOSectionType.RODATA, rodataOffset, rodataSize);
        this.sections[NXOSectionType.DATA.ordinal()]   = new NXOSection(NXOSectionType.DATA,   dataOffset,  dataSize);
    }

    private byte[] decompressSection(NXOSectionType type, long decompSize,
                                    boolean isZbic, LZ4SafeDecompressor lz4)
        throws IOException
    {
        if (decompSize == 0)
            return new byte[0];

        if (!this.nso0.isSectionCompressed(type))
        {
            return this.fileProvider.readBytes(
                this.nso0.getSectionFileOffset(type), decompSize);
        }

        byte[] compressed = this.fileProvider.readBytes(
            this.nso0.getSectionFileOffset(type),
            this.nso0.getCompressedSectionSize(type));

        if (isZbic)
        {
            try
            {
                byte[] out = ZbicUtil.decompress(compressed);
                if (out.length != decompSize)
                {
                    throw new IOException(String.format(
                        "ZBIC %s size mismatch: got %d, expected %d",
                        type, out.length, decompSize));
                }
                return out;
            }
            catch (ZbicException e)
            {
                throw new IOException("Failed to decompress ZBIC " + type + " section", e);
            }
        }
        else
        {
            byte[] out = new byte[Math.toIntExact(decompSize)];
            try
            {
                // Unlike the fast decoder, the safe decoder respects the
                // compressed input length and reports a malformed block.
                int decodedSize = lz4.decompress(
                    compressed, 0, compressed.length, out, 0, out.length);
                if (decodedSize != out.length)
                {
                    throw new IOException(String.format(
                        "LZ4 %s size mismatch: decoded %d, expected %d",
                        type, decodedSize, out.length));
                }
            }
            catch (LZ4Exception e)
            {
                throw new IOException(String.format(
                    "Invalid LZ4 %s section: stored=0x%X expanded=0x%X; " +
                    "NSO flags may not describe actual segment compression",
                    type, compressed.length, decompSize), e);
            }
            return out;
        }
    }

    @Override
    public ByteProvider getMemoryProvider() 
    {
        return this.memoryProvider;
    }

    @Override
    public NXOSection[] getSections() 
    {
        return this.sections;
    }
}
