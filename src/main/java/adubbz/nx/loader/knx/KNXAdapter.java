/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.knx;

import java.io.IOException;

import adubbz.nx.loader.nxo.MOD0Adapter;
import adubbz.nx.loader.nxo.NXOSection;
import adubbz.nx.loader.nxo.NXOSectionType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

// We don't have a MOD0, but inherit from the adapter anyway to reduce redundancy
public class KNXAdapter extends MOD0Adapter
{
    private static final long LEGACY_MAP_MARKER = 0xD51C403EL;
    private static final long INI1_MAGIC = 0x31494E49L;
    private static final long MODERN_BRANCH_MASK = 0xFF000000L;
    private static final long MODERN_BRANCH_VALUE = 0x14000000L;
    private static final long COMMON_MAP_SIZE = 0x30;

    protected KNXMapHeader map;
    
    protected ByteProvider memoryProvider;
    protected NXOSection[] sections;

    private static class MapLocation
    {
        final int offset;
        final long adjustment;

        MapLocation(int offset, long adjustment)
        {
            this.offset = offset;
            this.adjustment = adjustment;
        }
    }
    
    public KNXAdapter(Program program, ByteProvider fileProvider)
    {
        super(program, fileProvider);
        
        try
        {
            this.read();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("Failed to read KNX", e);
        }
    }

    public static boolean isKernel(ByteProvider provider) throws IOException
    {
        return findMap(provider) != null;
    }

    private static long readUnsignedInt(BinaryReader reader, long offset) throws IOException
    {
        long previous = reader.getPointerIndex();
        reader.setPointerIndex(offset);
        long value = reader.readNextUnsignedInt();
        reader.setPointerIndex(previous);
        return value;
    }

    private static boolean hasExpectedIni1(ByteProvider provider, BinaryReader reader, KNXMapHeader map) throws IOException
    {
        long ini1Offset = map.getIni1FileOffset();
        long length = provider.length();

        // Kernel-only dumps intentionally end exactly where embedded INI1
        // begins. Accept that boundary without requiring the stripped magic.
        if (ini1Offset == length)
            return true;

        if (ini1Offset < 0 || ini1Offset + 4 > length)
            return false;

        return readUnsignedInt(reader, ini1Offset) == INI1_MAGIC;
    }

    private static MapLocation findValidatedMap(ByteProvider provider, BinaryReader reader,
        long start, long end, boolean relative) throws IOException
    {
        long length = provider.length();
        long searchEnd = Math.min(end, length - COMMON_MAP_SIZE + 1);

        for (long offset = start; offset < searchEnd; offset += 4)
        {
            long adjustment = relative ? offset : 0;
            KNXMapHeader candidate = new KNXMapHeader(reader, Math.toIntExact(offset), adjustment);

            if (candidate.isValid(length) && hasExpectedIni1(provider, reader, candidate))
                return new MapLocation(Math.toIntExact(offset), adjustment);
        }

        return null;
    }

    private static MapLocation findMap(ByteProvider provider) throws IOException
    {
        long length = provider.length();

        if (length < COMMON_MAP_SIZE)
            return null;

        BinaryReader reader = new BinaryReader(provider, true);

        // 17.0.0+ kernels begin with a branch into rodata. The kernel map is
        // stored near that branch target and its offsets are relative to the
        // map's own location. This mirrors hactool's modern-kernel discovery.
        if (length >= 8)
        {
            reader.setPointerIndex(0);
            long firstInstruction = reader.readNextUnsignedInt();
            long secondInstruction = reader.readNextUnsignedInt();

            if ((firstInstruction & MODERN_BRANCH_MASK) == MODERN_BRANCH_VALUE && secondInstruction == 0)
            {
                long branchTarget = (firstInstruction & 0x00FFFFFFL) << 2;

                if (branchTarget < length)
                {
                    MapLocation modern = findValidatedMap(
                        provider,
                        reader,
                        branchTarget,
                        branchTarget + 0x1000,
                        true);

                    if (modern != null)
                        return modern;
                }
            }
        }

        // Pre-17.0.0 kernels store absolute map offsets near the beginning of
        // the kernel. Prefer structural validation plus the INI1 boundary.
        MapLocation legacy = findValidatedMap(provider, reader, 0, 0x1000, false);
        if (legacy != null)
            return legacy;

        // Preserve the loader's original marker-based fallback for older
        // kernels that do not satisfy the stronger structural check above.
        reader.setPointerIndex(0);
        long markerSearchEnd = Math.min(0x2000, length);

        while (reader.getPointerIndex() + 4 <= markerSearchEnd)
        {
            long markerOffset = reader.getPointerIndex();
            long candidate = reader.readNextUnsignedInt();

            if (candidate == LEGACY_MAP_MARKER)
            {
                long mapOffset = markerOffset - COMMON_MAP_SIZE;

                if (mapOffset >= 0)
                    return new MapLocation(Math.toIntExact(mapOffset), 0);
            }
        }

        return null;
    }
    
    private void read() throws IOException
    {
        Msg.info(this, "Reading...");

        MapLocation mapLocation = findMap(this.fileProvider);
        if (mapLocation == null)
            throw new IOException("Failed to find kernel map");

        this.map = new KNXMapHeader(this.fileReader, mapLocation.offset, mapLocation.adjustment);
        
        long textOffset = this.map.getTextFileOffset();
        long rodataOffset = this.map.getRodataFileOffset();
        long dataOffset = this.map.getDataFileOffset();
        long textSize = this.map.getTextSize();
        long rodataSize = this.map.getRodataSize();
        long dataSize = this.map.getDataSize();

        Msg.info(this, String.format("Kernel map offset: 0x%X", mapLocation.offset));
        Msg.info(this, String.format("Text size: 0x%X", textSize));
        
        // The data section is last, so we use its offset + decompressed size
        byte[] full = new byte[Math.toIntExact(dataOffset + dataSize)];

        byte[] text = this.fileProvider.readBytes(textOffset, textSize);
        System.arraycopy(text, 0, full, Math.toIntExact(textOffset), Math.toIntExact(textSize));

        byte[] rodata = this.fileProvider.readBytes(rodataOffset, rodataSize);
        System.arraycopy(rodata, 0, full, Math.toIntExact(rodataOffset), Math.toIntExact(rodataSize));

        byte[] data = this.fileProvider.readBytes(dataOffset, dataSize);
        System.arraycopy(data, 0, full, Math.toIntExact(dataOffset), Math.toIntExact(dataSize));
        this.memoryProvider = new ByteArrayProvider(full);
        
        this.sections = new NXOSection[3];
        this.sections[NXOSectionType.TEXT.ordinal()] = new NXOSection(NXOSectionType.TEXT, textOffset, textSize);
        this.sections[NXOSectionType.RODATA.ordinal()] = new NXOSection(NXOSectionType.RODATA, rodataOffset, rodataSize);
        this.sections[NXOSectionType.DATA.ordinal()] = new NXOSection(NXOSectionType.DATA, dataOffset, dataSize);
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

    @Override
    public long getDynamicOffset() 
    {
        return this.map.getDynamicOffset();
    }

    @Override
    public long getBssOffset()
    {
        return this.map.getBssFileOffset();
    }
    
    @Override
    public long getBssSize()
    {
        return this.map.getBssSize();
    }
    
    @Override
    public long getGotOffset()
    {
        ElfDynamicTable dt = this.getDynamicTable(this.program);
        
        if (dt == null)
            return 0;
        
        return dt.getAddressOffset() + dt.getLength();
    }
    
    @Override
    public long getGotSize()
    {
        ElfDynamicTable dt = this.getDynamicTable(this.program);
        
        if (dt == null || !dt.containsDynamicValue(ElfDynamicType.DT_INIT_ARRAY))
            return 0;
        
        try 
        {
            return this.program.getImageBase().getOffset() + dt.getDynamicValue(ElfDynamicType.DT_INIT_ARRAY) - this.getGotOffset();
        } 
        catch (NotFoundException e) 
        {
            return 0;
        }
    }
}
