// ProbeSwitchGot.java
// Read-only diagnostic for GOT discovery in imported Nintendo Switch NSO modules.
//@category Nintendo Switch

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;

public class ProbeSwitchGot extends GhidraScript {
    private static final int MAX_RUNS = 15;
    private Memory mem;
    private long imageBase;

    private static class Run implements Comparable<Run> {
        long begin, end;
        int slots;
        Run(long b, long e, int n) { begin = b; end = e; slots = n; }
        @Override
        public int compareTo(Run rhs) {
            int bySize = Integer.compare(rhs.slots, slots);
            return bySize != 0 ? bySize : Long.compare(begin, rhs.begin);
        }
    }

    private void showBlock(String name) {
        MemoryBlock block = mem.getBlock(name);
        if (block == null) {
            println(name + ": (not defined)");
        } else {
            println(String.format("%s: %s..%s (0x%X bytes)",
                name, block.getStart(), block.getEnd(), block.getSize()));
        }
    }

    private void printRuns(String caption, TreeSet<Long> addresses) {
        ArrayList<Run> runs = new ArrayList<>();
        if (!addresses.isEmpty()) {
            long start = addresses.first(), end = start;
            int count = 1;
            for (long x : addresses.tailSet(start, false)) {
                if (x > end && x - end == 8) {
                    end = x;
                    count++;
                } else {
                    runs.add(new Run(start, end, count));
                    start = end = x;
                    count = 1;
                }
            }
            runs.add(new Run(start, end, count));
        }
        Collections.sort(runs);
        println(caption + ": " + addresses.size() + " distinct relocation targets; " +
            runs.size() + " contiguous runs");
        for (int i = 0; i < Math.min(MAX_RUNS, runs.size()); i++) {
            Run run = runs.get(i);
            long start = run.begin + imageBase;
            long end = run.end + imageBase + 8;
            println(String.format("  %d: relative=0x%X..0x%X absolute=0x%X..0x%X slots=%d",
                i + 1, run.begin, run.end + 8, start, end, run.slots));
        }
    }

    private void dumpRelas(String name, TreeSet<Long> targets) throws Exception {
        MemoryBlock block = mem.getBlock(name);
        if (block == null) {
            println(name + ": not present");
            return;
        }
        if (block.getSize() % 24 != 0) {
            println(name + ": malformed size, not a multiple of 24");
            return;
        }
        long count = block.getSize() / 24;
        Map<Long, Integer> types = new HashMap<>();
        for (long i = 0; i < count; i++) {
            monitor.checkCancelled();
            Address at = block.getStart().add(24 * i);
            long offset = mem.getLong(at);
            long info = mem.getLong(at.add(8));
            long type = info & 0xffffffffL;
            types.merge(type, 1, Integer::sum);
            if (offset >= 0 && offset < Integer.MAX_VALUE) {
                targets.add(offset);
            }
        }
        println(name + " entries=" + count + " relocation types=" + types);
        printRuns(name + " target clusters", targets);
    }

    private void dumpRelr(TreeSet<Long> targets) throws Exception {
        MemoryBlock block = mem.getBlock(".relr.dyn");
        if (block == null) {
            println(".relr.dyn: not present");
            return;
        }
        if (block.getSize() % 8 != 0) {
            println(".relr.dyn: malformed size");
            return;
        }
        long base = 0;
        for (long i = 0; i < block.getSize() / 8; i++) {
            monitor.checkCancelled();
            long entry = mem.getLong(block.getStart().add(i * 8));
            if ((entry & 1) == 0) {
                targets.add(entry);
                base = entry + 8;
            } else {
                for (int bit = 1; bit <= 63; bit++) {
                    if ((entry & (1L << bit)) != 0) {
                        targets.add(base + 8L * (bit - 1));
                    }
                }
                base += 63L * 8L;
            }
        }
        printRuns(".relr.dyn target clusters", targets);
    }

    private void dumpDynamic() throws Exception {
        MemoryBlock block = mem.getBlock(".dynamic");
        if (block == null) {
            println(".dynamic unavailable, can't examine DT_PLTGOT and other anchors");
            return;
        }
        Map<Long, Long> found = new HashMap<>();
        long entries = Math.min(block.getSize() / 16, 4096L);
        for (long i = 0; i < entries; i++) {
            monitor.checkCancelled();
            Address a = block.getStart().add(i * 16);
            long tag = mem.getLong(a);
            long val = mem.getLong(a.add(8));
            if (tag == 0) break;
            found.put(tag, val);
        }
        long[] tags = { 3, 7, 8, 9, 23, 2, 25, 27, 35, 36, 37 };
        String[] names = { "DT_PLTGOT", "DT_RELA", "DT_RELASZ",
            "DT_RELAENT", "DT_JMPREL", "DT_PLTRELSZ", "DT_INIT_ARRAY",
            "DT_INIT_ARRAYSZ", "DT_RELRSZ", "DT_RELR", "DT_RELRENT" };
        for (int i = 0; i < tags.length; i++) {
            Long val = found.get(tags[i]);
            println(names[i] + "=" + (val == null ? "(absent)" :
                String.format("0x%X", val)));
        }
        println(String.format("Historical GOT guess: dynamic offset 0x%X + size 0x%X",
            block.getStart().getOffset() - imageBase, block.getSize()));
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("Open the imported NSO in CodeBrowser first.");
            return;
        }
        mem = currentProgram.getMemory();
        imageBase = currentProgram.getImageBase().getOffset();
        println("NSO GOT probe: " + currentProgram.getName() +
            " imageBase=" + currentProgram.getImageBase());
        for (String name : new String[] {
            ".text", ".rodata", ".data", ".dynamic", ".got", ".got.plt",
            ".rela.dyn", ".rela.plt", ".relr.dyn", ".init_array" }) {
            showBlock(name);
        }
        dumpDynamic();
        dumpRelas(".rela.dyn", new TreeSet<>());
        dumpRelas(".rela.plt", new TreeSet<>());
        dumpRelr(new TreeSet<>());
        println("Read-only: no sections, labels or datatypes modified.");
    }
}
