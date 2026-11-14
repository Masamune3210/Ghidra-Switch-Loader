/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.knx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class KNXMapHeader 
{
    private long textOffset;
    private long textEndOffset;
    private long rodataOffset;
    private long rodataEndOffset;
    private long dataOffset;
    private long dataEndOffset;
    private long bssOffset;
    private long bssEndOffset;
    private long ini1Offset;
    private long dynamicOffset;
    private long initArrayOffset;
    private long initArrayEndOffset;
    
    public KNXMapHeader(BinaryReader reader, int readerOffset)
    {
        this(reader, readerOffset, 0);
    }

    public KNXMapHeader(BinaryReader reader, int readerOffset, long adjustment)
    {
        long prevPointerIndex = reader.getPointerIndex();
        
        reader.setPointerIndex(readerOffset);
        this.readHeader(reader, adjustment);
        
        // Restore the previous pointer index
        reader.setPointerIndex(prevPointerIndex);
    }

    private static long adjustOffset(long value, long adjustment)
    {
        // Kernel map offsets are 32-bit values. On 17.0.0+ they are relative
        // to the map itself and may represent negative offsets, so mirror the
        // uint32_t wraparound used by Nintendo/hactool when rebasing them.
        return (value + adjustment) & 0xFFFFFFFFL;
    }

    private void readHeader(BinaryReader reader, long adjustment)
    {
        try 
        {
            this.textOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.textEndOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.rodataOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.rodataEndOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.dataOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.dataEndOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.bssOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.bssEndOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.ini1Offset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.dynamicOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.initArrayOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
            this.initArrayEndOffset = adjustOffset(reader.readNextUnsignedInt(), adjustment);
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read KNX Map header");
        }
    }

    public boolean isValid(long maxSize)
    {
        if (maxSize < 0)
            return false;

        if (this.textOffset != 0)
            return false;
        if (this.textOffset >= this.textEndOffset)
            return false;
        if ((this.textEndOffset & 0xFFF) != 0)
            return false;
        if (this.textEndOffset > this.rodataOffset)
            return false;
        if ((this.rodataOffset & 0xFFF) != 0)
            return false;
        if (this.rodataOffset >= this.rodataEndOffset)
            return false;
        if ((this.rodataEndOffset & 0xFFF) != 0)
            return false;
        if (this.rodataEndOffset > this.dataOffset)
            return false;
        if ((this.dataOffset & 0xFFF) != 0)
            return false;
        if (this.dataOffset >= this.dataEndOffset)
            return false;
        if (this.dataEndOffset > this.bssOffset)
            return false;
        if (this.bssOffset > this.bssEndOffset)
            return false;
        if (this.bssEndOffset > this.ini1Offset)
            return false;

        // A full package2 kernel contains INI1 at ini1Offset. A kernel-only
        // image may intentionally be truncated exactly at that boundary.
        if (this.ini1Offset > maxSize)
            return false;
        if (this.ini1Offset < maxSize && maxSize - this.ini1Offset < 0x10)
            return false;

        return true;
    }
    
    public long getTextFileOffset()
    {
        return this.textOffset;
    }
    
    public long getTextSize()
    {
        return this.textEndOffset - this.textOffset;
    }
    
    public long getRodataFileOffset()
    {
        return this.rodataOffset;
    }
    
    public long getRodataSize()
    {
        return this.rodataEndOffset - this.rodataOffset;
    }
    
    public long getDataFileOffset()
    {
        return this.dataOffset;
    }
    
    public long getDataSize()
    {
        return this.dataEndOffset - this.dataOffset;
    }
    
    public long getBssFileOffset()
    {
        return this.bssOffset;
    }
    
    public long getBssSize()
    {
        return this.bssEndOffset - this.bssOffset;
    }

    public long getIni1FileOffset()
    {
        return this.ini1Offset;
    }
    
    public long getDynamicOffset()
    {
        return this.dynamicOffset;
    }
}
