// ValidateSwitchGot.java
// Read-only evidence gathering: determine whether the pre-PLT gap is all GOT
// or mixes GOT with other relocated data.
//@category Nintendo Switch

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

public class ValidateSwitchGot extends GhidraScript {
    private static final long R_AARCH64_ABS64 = 257;
    private static final long R_AARCH64_GLOB_DAT = 1025;
    private static final long R_AARCH64_JUMP_SLOT = 1026;
    private static final int PAGE = 0x1000;
    private Memory memory;
    private long imageBase;

    private Address at(long relative) {
        return currentProgram.getImageBase().add(relative);
    }

    private long relative(Address addr) {
        return addr.getOffset() - imageBase;
    }

    private static class Counts {
        int globDat, abs64, jumpSlot, relr;
        int zero, mapped, unmapped, textRefs, otherRefs, mappedSlots;
    }

    private void collectRela(String blockName, long start, long end,
            Set<Long> globDat, Set<Long> abs64, Set<Long> jumpSlots) throws Exception {
        MemoryBlock b = memory.getBlock(blockName);
        if (b == null) {
            println(blockName + ": no memory block");
            return;
        }
        if (b.getSize() % 24 != 0) {
            println(blockName + ": invalid RELA size (not multiple of 24)");
            return;
        }
        long[] types = new long[3];
        for (long i = 0; i < b.getSize() / 24; ++i) {
            monitor.checkCancelled();
            Address record = b.getStart().add(i * 24);
            long target = memory.getLong(record);
            long type = memory.getLong(record.add(8)) & 0xffffffffL;
            if (type == R_AARCH64_GLOB_DAT) {
                types[0]++;
                globDat.add(target);
            } else if (type == R_AARCH64_ABS64) {
                types[1]++;
                if (target >= start && target < end)
                    abs64.add(target);
            } else if (type == R_AARCH64_JUMP_SLOT) {
                types[2]++;
                jumpSlots.add(target);
            }
        }
        println(String.format("%s: GLOB_DAT=%d ABS64=%d JUMP_SLOT=%d",
            blockName, types[0], types[1], types[2]));
    }

    private void collectRelr(long start, long end, Set<Long> relr) throws Exception {
        MemoryBlock b = memory.getBlock(".relr.dyn");
        if (b == null) {
            println(".relr.dyn: missing");
            return;
        }
        if (b.getSize() % 8 != 0) {
            println(".relr.dyn: invalid size");
            return;
        }
        long base = 0;
        for (long i = 0; i < b.getSize() / 8; ++i) {
            monitor.checkCancelled();
            long encoded = memory.getLong(b.getStart().add(i * 8));
            if ((encoded & 1) == 0) {
                if (encoded >= start && encoded < end)
                    relr.add(encoded);
                base = encoded + 8;
            } else {
                for (int bit = 1; bit <= 63; ++bit) {
                    if ((encoded & (1L << bit)) != 0) {
                        long target = base + (bit - 1L) * 8;
                        if (target >= start && target < end)
                            relr.add(target);
                    }
                }
                base += 63 * 8L;
            }
        }
        println(".relr.dyn: " + relr.size() + " targets inside candidate");
    }

    private void describeGlobDat(long start, long end, Set<Long> globDat) throws Exception {
        println("Individual R_AARCH64_GLOB_DAT targets (the strongest GOT evidence):");
        int inside = 0;
        for (long target : new TreeSet<>(globDat)) {
            monitor.checkCancelled();
            boolean contained = target >= start && target < end;
            if (contained) inside++;
            String destination = "(not mapped)";
            String value = "(unreadable)";
            if (target >= 0 && target <= Integer.MAX_VALUE) {
                Address slot = at(target);
                if (memory.contains(slot)) {
                    long ptr = memory.getLong(slot);
                    value = String.format("0x%X", ptr);
                    MemoryBlock block = memory.getBlock(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(ptr));
                    destination = block == null ? "unmapped/zero" : block.getName();
                }
            }
            println(String.format(
                "  target=0x%X absolute=0x%X inCandidate=%s value=%s -> %s",
                target, imageBase + target, contained, value, destination));
        }
        println(String.format("GLOB_DAT inside candidate: %d/%d",
            inside, globDat.size()));
    }

    private void summarize(long start, long end, Set<Long> globDat,
            Set<Long> abs64, Set<Long> jumpSlots, Set<Long> relr) throws Exception {
        int bins = (int)((end - start + PAGE - 1) / PAGE);
        Counts[] stats = new Counts[bins];
        for (int i = 0; i < bins; ++i) stats[i] = new Counts();

        for (long p = start; p < end; p += 8) {
            monitor.checkCancelled();
            Counts c = stats[(int)((p - start) / PAGE)];
            if (globDat.contains(p)) c.globDat++;
            if (abs64.contains(p)) c.abs64++;
            if (jumpSlots.contains(p)) c.jumpSlot++;
            if (relr.contains(p)) c.relr++;

            Address slot = at(p);
            MemoryBlock owner = memory.getBlock(slot);
            if (owner != null) {
                c.mappedSlots++;
                long value = memory.getLong(slot);
                if (value == 0) {
                    c.zero++;
                } else {
                    MemoryBlock targetBlock = memory.getBlock(
                        currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value));
                    if (targetBlock != null) c.mapped++;
                    else c.unmapped++;
                }
                ReferenceIterator iter = currentProgram.getReferenceManager().getReferencesTo(slot);
                while (iter.hasNext()) {
                    Reference ref = iter.next();
                    MemoryBlock from = memory.getBlock(ref.getFromAddress());
                    if (from != null && from.isExecute()) c.textRefs++;
                    else c.otherRefs++;
                }
            }
        }
        println("Per-4KiB density. 'mapped' means pointer value resolves to existing Ghidra memory;");
        println("'textRefs' counts Ghidra-discovered code references, which depend on auto-analysis.");
        println("         Range (relative)       slots  GLOB  ABS64  RELR  PLT   zero  mapped  other  textRefs");
        for (int i = 0; i < bins; ++i) {
            long lo = start + i * (long)PAGE;
            long hi = Math.min(end, lo + PAGE);
            Counts c = stats[i];
            println(String.format(
                "  0x%09X..0x%09X %5d %5d %6d %5d %4d %6d %7d %6d %9d",
                lo, hi, c.mappedSlots, c.globDat, c.abs64, c.relr,
                c.jumpSlot, c.zero, c.mapped, c.unmapped, c.textRefs));
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null)
            throw new IllegalStateException("Open one imported NSO in CodeBrowser.");
        memory = currentProgram.getMemory();
        imageBase = currentProgram.getImageBase().getOffset();
        MemoryBlock dynamic = memory.getBlock(".dynamic");
        MemoryBlock plt = memory.getBlock(".got.plt");
        if (dynamic == null || plt == null) {
            println("Need both .dynamic and .got.plt blocks. No GOT guessed.");
            return;
        }
        long start = relative(dynamic.getEnd()) + 1;
        long end = relative(plt.getStart());
        if (start < 0 || end <= start || end - start > 0x1000000L) {
            println("Invalid or unusually large candidate interval. No GOT guessed.");
            return;
        }

        println(String.format("Program=%s base=0x%X; CANDIDATE ONLY: [0x%X, 0x%X), 0x%X bytes",
            currentProgram.getName(), imageBase, start, end, end - start));
        println("An NSO has no ELF section headers establishing that this entire interval is .got.");
        Set<Long> globDat = new HashSet<>();
        Set<Long> abs64 = new HashSet<>();
        Set<Long> jumpSlots = new HashSet<>();
        Set<Long> relr = new HashSet<>();
        collectRela(".rela.dyn", start, end, globDat, abs64, jumpSlots);
        collectRela(".rela.plt", start, end, globDat, abs64, jumpSlots);
        collectRelr(start, end, relr);
        describeGlobDat(start, end, globDat);
        summarize(start, end, globDat, abs64, jumpSlots, relr);
        println("Read-only: no GOT created, memory altered, or pointer datatype applied.");
        println("Relocation density alone CANNOT prove every slot is a GOT entry.");
    }
}
