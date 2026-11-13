/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import adubbz.nx.common.ElfCompatibilityProvider;
import adubbz.nx.common.InvalidMagicException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfDynamic;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import adubbz.nx.common.NXRelocation;
import adubbz.nx.loader.nxo.NXOSectionType;

/*
 * An adapter implementation for binaries with a MOD0 section.
 */
public abstract class MOD0Adapter extends NXOAdapter
{
    protected Program program;
    protected MOD0Header mod0;
    
    public MOD0Adapter(Program program, ByteProvider fileProvider)
    {
        super(fileProvider);
        this.program = program;
    }
    
    @Override
    public long getDynamicOffset()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        return mod0.getDynamicOffset();
    }
    
    @Override
    public long getDynamicSize()
    {
        assert this.program != null;
        
        if (this.getElfProvider(this.program).getDynamicTable() != null)
            return this.getElfProvider(this.program).getDynamicTable().getLength();
        
        long dtSize = 0;
        var reader = new BinaryReader(this.getMemoryProvider(), true);
        reader.setPointerIndex(this.getDynamicOffset());
        
        try
        {
            while (true) 
            {
                ElfDynamic dyn = new ElfDynamic(reader, new ElfCompatibilityProvider.DummyElfHeader(this.isAarch32()));
                dtSize += dyn.sizeof();
                if (dyn.getTag() == ElfDynamicType.DT_NULL.value) 
                {
                    break;
                }
            }
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to get dynamic size", e);
        } catch (ElfException e) {
            Msg.error(this, "Can't construct DummyElfHeader", e);
        }

        return dtSize;
    }
    
    @Override
    public long getBssOffset()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        return mod0.getBssStartOffset();
    }
    
    @Override
    public long getBssSize()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        return mod0.getBssSize();
    }

    private long gotOffset = 0;
    private long gotSize = 0;
    private boolean gotExamined = false;

    private boolean findGot()
    {
        assert this.program != null;

        // One negative result is enough. Import code queries both offset and
        // size repeatedly, including after attempting to create the block.
        if (gotExamined)
            return gotSize > 0;
        gotExamined = true;

        MOD0Header mod0 = this.getMOD0();
        if (mod0 == null)
            return false;

        long imageBase = program.getImageBase().getOffset();

        if (mod0.hasLibnxExtension())
        {
            this.gotOffset = mod0.getLibnxGotStart() + imageBase;
            this.gotSize = mod0.getLibnxGotEnd() - mod0.getLibnxGotStart();
            return gotSize > 0;
        }

        // The old heuristic started AFTER .got.plt when it was present.
        // On modern NSOs, the ordinary GOT instead sits BETWEEN the end of
        // .dynamic and the start of .got.plt, with relocated pointer slots
        // throughout. Both ends are section anchors, not guessed addresses.
        Set<Long> relocationOffsets = new HashSet<>();
        for (NXRelocation reloc : this.getRelocations(program))
            relocationOffsets.add(reloc.offset);

        MemoryBlock gotPlt = program.getMemory().getBlock(".got.plt");
        long dynamicEnd = this.getDynamicOffset() + this.getDynamicSize();
        int pointerSize = this.getOffsetSize();

        if (gotPlt != null)
        {
            NXOSection dataSection = getSection(NXOSectionType.DATA);
            long pltStart = gotPlt.getStart().getOffset() - imageBase;
            long[] range = GotRegionDetector.detectBeforePlt(
                dynamicEnd, pltStart, dataSection.getOffset(), dataSection.getSize(),
                pointerSize, relocationOffsets);

            if (range != null)
            {
                gotOffset = imageBase + range[0];
                gotSize = range[1] - range[0];
                Msg.info(this, String.format(
                    "Located pre-PLT .got: relative 0x%X..0x%X (size 0x%X)",
                    range[0], range[1], gotSize));
                return true;
            }
        }

        // Preserve legacy behavior for older Switch modules. A HashSet
        // avoids thousands of linear scans through large RELR tables.
        long gotStart = gotPlt != null
            ? gotPlt.getEnd().getOffset() + 1 - imageBase
            : dynamicEnd;
        long gotEnd = gotStart + pointerSize;
        long initArrayValue;

        try
        {
            initArrayValue = this.getDynamicTable(program).getDynamicValue(
                ElfDynamicType.DT_INIT_ARRAY);
        }
        catch (NotFoundException ignored)
        {
            initArrayValue = -1;
        }

        while ((relocationOffsets.contains(gotEnd) ||
                (gotPlt == null && initArrayValue != -1 && gotEnd < initArrayValue)) &&
                (initArrayValue == -1 || gotEnd < initArrayValue ||
                 gotStart > initArrayValue))
        {
            gotEnd += pointerSize;
        }

        if (gotEnd > gotStart + pointerSize)
        {
            gotOffset = imageBase + gotStart;
            gotSize = gotEnd - gotStart;
            return true;
        }

        Msg.warn(this, "Unable to identify .got section using dynamic anchors and relocation targets.");
        return false;
    }

    @Override
    public long getGotOffset()
    {
        if (this.findGot()) {
            return this.gotOffset;
        }

        return 0;
    }
    
    @Override
    public long getGotSize()
    {
        if (this.findGot()) {
            return this.gotSize;
        }

        return 0;
    }
    
    public MOD0Header getMOD0()
    {
        if (this.mod0 != null)
            return this.mod0;
        
        try 
        {
            long mod0Offset = this.getMemoryReader().readUnsignedInt(this.getSection(NXOSectionType.TEXT).getOffset() + 4);
        
            if (mod0Offset >= this.getMemoryProvider().length())
                throw new IllegalArgumentException("Mod0 offset is outside the binary!");
            
            this.mod0 = new MOD0Header(this.getMemoryReader(), mod0Offset, mod0Offset);
            return this.mod0;
        }
        catch (InvalidMagicException e)
        {
            Msg.error(this, "Invalid MOD0 magic.", e);
        }
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read MOD0.", e);
        }
        
        return null;
    }
}
