/* Disassemble and read the Exynos9825 BL2 embedded ARM32/Thumb DMC blob.
 *
 * The blob lives at file 0x18800..0x22400 inside the HWHA BL2 stage and runs in
 * its own address space (its movw/movt are absolute within 0x18xxx..0x21xxx).
 * This script, run on a program imported as ARM:LE:32:v7 (base 0x0), forces
 * Thumb over the blob range, disassembles from the known entries, creates
 * functions, decompiles the dispatcher and the static DREX bring-up, and does a
 * definitive movw/movt scan to check whether the blob ever forms the address of
 * the hardcoded rate table at 0x33fb0 or the ECT (0x36c00) -- i.e. whether the
 * blob, rather than a separate image (ACPM), consumes 0x33fb0.
 *
 * HEADLESS INVOCATION
 *   GH=/home/chanz22/ghidra_12.1.4_PUBLIC_20260921/ghidra_12.1.4_PUBLIC/support/analyzeHeadless
 *   REPO=/home/chanz22/Documents/GitHub/exynos9825-payloads
 *   "$GH" /home/chanz22/ghidra_projects exy9825_thumb \
 *     -import /home/chanz22/EUB-N10/hwha_stages/bl2.bin \
 *     -processor ARM:LE:32:v7 -loader BinaryLoader -loader-baseAddr 0x0 \
 *     -scriptPath "$REPO/tools/ghidra" \
 *     -postScript Exy9825_ThumbBlob.java "$REPO/build/thumb_blob_report.txt" \
 *     -deleteProject
 *
 * @category Exynos9825
 */

import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

public class Exy9825_ThumbBlob extends GhidraScript {

    private static final long BLOB_START = 0x18000L;
    private static final long BLOB_END   = 0x22400L;
    private static final long[] SEEDS = {
        0x20c08L, 0x20c38L, 0x20c5cL, 0x20ca4L, 0x20cd0L,
        0x20d54L, 0x20d5cL, 0x21348L, 0x22840L, 0x228f0L
    };

    private final List<String> lines = new ArrayList<String>();
    private void out(String s) { println(s); lines.add(s); }

    @Override
    public void run() throws Exception {
        Address s = toAddr(BLOB_START), e = toAddr(BLOB_END);
        Listing listing = currentProgram.getListing();

        out("Exy9825 Thumb DMC blob read; blob 0x" + Long.toHexString(BLOB_START)
                + "..0x" + Long.toHexString(BLOB_END));

        // Force Thumb over the blob and (re)disassemble from the known entries.
        clearListing(s, e);
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode != null) {
            currentProgram.getProgramContext().setValue(tmode, s, e, BigInteger.ONE);
            out("[tmode] set TMode=1 over blob range");
        } else {
            out("[tmode] WARNING: no TMode register; language may be wrong");
        }

        Set<Address> funcs = new LinkedHashSet<Address>();
        for (long seed : SEEDS) {
            Address a = toAddr(seed);
            disassemble(a);
            Function f = createFunction(a, null);
            if (f != null) funcs.add(a);
        }
        // Follow one level of BL/BLX targets and make them functions too.
        Set<Address> moreTargets = new LinkedHashSet<Address>();
        InstructionIterator it0 = listing.getInstructions(s, true);
        while (it0.hasNext()) {
            Instruction ins = it0.next();
            if (ins.getAddress().getOffset() >= BLOB_END) break;
            String m = ins.getMnemonicString().toLowerCase();
            if (m.startsWith("bl") || m.equals("b") || m.startsWith("blx")) {
                Reference[] fr = ins.getReferencesFrom();
                for (Reference r : fr) {
                    Address t = r.getToAddress();
                    if (t.getOffset() >= BLOB_START && t.getOffset() < BLOB_END) {
                        moreTargets.add(t);
                    }
                }
            }
        }
        for (Address t : moreTargets) {
            disassemble(t);
            Function f = createFunction(t, null);
            if (f != null) funcs.add(t);
        }
        out("[funcs] created " + funcs.size() + " functions in the blob");

        // Definitive movw/movt scan: reconstruct address constants and flag any
        // that point at the hardcoded table / ECT (outside the blob).
        scanMovwMovt(listing, s);

        // Decompile the dispatcher and the static DREX bring-up for reading.
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        long[] readThese = { 0x20c38L, 0x20d5cL, 0x20c08L, 0x20ca4L };
        for (long fa : readThese) {
            Function f = getFunctionAt(toAddr(fa));
            if (f == null) continue;
            out("");
            out("---------------- decompile 0x" + Long.toHexString(fa) + " ----------------");
            try {
                DecompileResults res = di.decompileFunction(f, 90, monitor);
                if (res != null && res.decompileCompleted())
                    out(res.getDecompiledFunction().getC());
                else
                    out("  // decompile did not complete");
            } catch (Exception ex) {
                out("  // decompile error: " + ex);
            }
        }
        di.dispose();

        String report = "/home/chanz22/Documents/GitHub/exynos9825-payloads/build/thumb_blob_report.txt";
        String[] args = getScriptArgs();
        if (args != null && args.length >= 1) report = args[0];
        try {
            PrintWriter w = new PrintWriter(report);
            for (String l : lines) w.println(l);
            w.close();
            println("[report] wrote " + report);
        } catch (Exception ex) {
            println("[report] could not write " + report + ": " + ex);
        }
    }

    private void scanMovwMovt(Listing listing, Address start) {
        Map<String, Long> low = new HashMap<String, Long>();   // reg -> movw value
        Map<Long, List<Address>> consts = new HashMap<Long, List<Address>>();
        List<String> flags = new ArrayList<String>();
        InstructionIterator it = listing.getInstructions(start, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().getOffset() >= BLOB_END) break;
            String m = ins.getMnemonicString().toLowerCase();
            if (m.equals("movw")) {
                String reg = ins.getRegister(0) != null ? ins.getRegister(0).getName() : null;
                Scalar sc = scalarOf(ins, 1);
                if (reg != null && sc != null) low.put(reg, sc.getUnsignedValue() & 0xffff);
            } else if (m.equals("movt")) {
                String reg = ins.getRegister(0) != null ? ins.getRegister(0).getName() : null;
                Scalar sc = scalarOf(ins, 1);
                if (reg != null && sc != null && low.containsKey(reg)) {
                    long v = low.get(reg) | ((sc.getUnsignedValue() & 0xffff) << 16);
                    List<Address> l = consts.get(v);
                    if (l == null) { l = new ArrayList<Address>(); consts.put(v, l); }
                    l.add(ins.getAddress());
                    if (v == 0x33fb0L || v == 0x33f60L || v == 0x33fb8L
                            || (v >= 0x36c00L && v < 0x4b000L)) {
                        flags.add(String.format("  !! 0x%08x formed at %s", v, ins.getAddress()));
                    }
                }
            }
        }
        out("");
        out("=== movw/movt address constants in the blob ===");
        out("does the blob form 0x33fb0 / 0x33f60 / the ECT? " +
                (flags.isEmpty() ? "NO (not referenced by the blob)" : "YES:"));
        for (String f : flags) out(f);
        // Show the out-of-blob constants it DOES form (MMIO + any cross refs).
        TreeSet<Long> keys = new TreeSet<Long>(consts.keySet());
        out("");
        out("out-of-blob constants the blob builds (first occurrence):");
        for (Long v : keys) {
            if (v >= BLOB_START && v < BLOB_END) continue;   // internal, skip
            if (v < 0x1000) continue;
            out(String.format("  0x%08x  (x%d)  e.g. %s",
                    v, consts.get(v).size(), consts.get(v).get(0)));
        }
    }

    private Scalar scalarOf(Instruction ins, int op) {
        for (Object o : ins.getOpObjects(op)) {
            if (o instanceof Scalar) return (Scalar) o;
        }
        return null;
    }
}
