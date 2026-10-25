/* Trace the Exynos9825 BL2 (AArch64) DMC / ECT rate->timing path.
 *
 * Goal: find the AArch64 functions that read the PARA2005 ECT, the hardcoded
 * MIF rate table at 0x33fb0, and the NEWTIME tables, then decompile them so the
 * rate->timing mapping (the code that fills the Thumb DMC blob's data region) is
 * readable. Static immediate/literal scanning outside Ghidra could not resolve
 * these because the tables are reached through runtime pointers (cal_init); let
 * Ghidra's recursive disassembly + reference analysis find the consumers.
 *
 * Runs on a program imported as AArch64 from the HWHA BL2 stage
 * (hwha_stages/bl2.bin), base 0x0. The Thumb DMC blob (0x18800..0x22400) is a
 * separate AArch32 image and needs its own program; see the note at the end.
 *
 * Java (not Jython) so it runs in stock headless with no extension.
 *
 * HEADLESS INVOCATION
 *   GH=/home/chanz22/ghidra_12.1.4_PUBLIC_20260921/ghidra_12.1.4_PUBLIC/support/analyzeHeadless
 *   REPO=/home/chanz22/Documents/GitHub/exynos9825-payloads
 *   "$GH" /home/chanz22/ghidra_projects exy9825_dmc_trace \
 *     -import /home/chanz22/EUB-N10/hwha_stages/bl2.bin \
 *     -processor AARCH64:LE:64:v8A -loader BinaryLoader -loader-baseAddr 0x0 \
 *     -scriptPath "$REPO/tools/ghidra" \
 *     -postScript Exy9825_DmcTrace.java "$REPO/build/dmc_trace_report.txt" \
 *     -deleteProject
 *
 * Thumb DMC blob (separate program, read its logic by hand or a companion
 * script): import the same file as ARM:LE:32:v7, base 0x0, force Thumb (TMode=1)
 * over 0x18800..0x22400 and disassemble from entries 0x20c08/0x20c38/0x20d5c.
 * Its data region (0x19000..0x1b000: context 0x1a934, enable table 0x19f94,
 * dispatch 0x19e70) is what the AArch64 fill code writes into.
 *
 * @category Exynos9825
 */

import java.io.PrintWriter;
import java.util.*;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class Exy9825_DmcTrace extends GhidraScript {

    // Data tables and anchors of interest (file offset == VA, BL2 at 0x0).
    private static final long[] TARGET_ADDR = {
        0x33fb0L, 0x33f60L, 0x36c00L, 0x37e10L, 0x3e0e8L
    };
    private static final String[] TARGET_DESC = {
        "mif_rate_config: hardcoded 10x{rate_kHz,code} in BL2 code",
        "dispatch/pointer table above the rate table",
        "ECT PARA2005 header",
        "ECT dvfs_mif rate column",
        "ECT NEWTIME block"
    };

    // NEWTIME numeric keys and rate constants a consumer is likely to materialise.
    private static final Map<Long, String> SCALARS = new LinkedHashMap<Long, String>();
    static {
        SCALARS.put(0x11111111L, "NEWTIME key 0x11111111");
        SCALARS.put(0xaa1L, "NEWTIME key aa1");
        SCALARS.put(0xac1L, "NEWTIME key ac1");
        SCALARS.put(0xca1L, "NEWTIME key ca1");
        SCALARS.put(0xb1L, "NEWTIME key b1");
        SCALARS.put(2093000L, "rate 2093000");
        SCALARS.put(2094000L, "rate 2094000");
        SCALARS.put(2132000L, "rate 2132000");
        SCALARS.put(2133000L, "rate 2133000");
    }

    private static final String[] STRINGS = {
        "PARA2005", "DRAM INFO MISMATCH", "NEWTIME", "dvfs_mif",
        "PLL_MIF", "SCI_dvfs_mif", "DMC ", "dramini", "mif_stat"
    };

    // Explicit functions to also decompile: the caller chain found in pass 1
    // (cal_init / select-by-DRAM-part / trainer) and the ECT access API, to see
    // where the DVFS level index and the DRAM-part id come from.
    private static final long[] FOLLOW = {
        0x2484L,            // caller of dvfs_cal_init (FUN_00001df8)
        0x604cL,            // caller of NEWTIME@2764 (select timing set by DRAM part)
        0x826cL,            // caller of the DRAM-info-mismatch trainer (0x7968)
        0x6084L, 0x8698L, 0x86d0L, 0x874cL, 0x87ccL, 0xeabcL, // callers of NEWTIME@dd74
        0x4668L, 0x49a0L, 0x464cL, 0x48b4L, 0x1928L, 0x6930L  // ECT access / alloc / abort
    };

    private static final Pattern IDENT =
        Pattern.compile("^[A-Za-z_][A-Za-z0-9_]{2,47}$");

    private final List<String> lines = new ArrayList<String>();

    private void out(String s) {
        println(s);
        lines.add(s);
    }

    private String fsig(Function f) {
        if (f == null) return "<no function>";
        return f.getName() + " @ " + f.getEntryPoint();
    }

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();

        out("Exy9825 DMC/ECT trace on " + currentProgram.getName());
        out("image base " + currentProgram.getImageBase()
                + ", " + fm.getFunctionCount() + " functions");

        recoverFuncNames(listing);

        TreeSet<Address> candidates = new TreeSet<Address>();
        refsToTargets(candidates);
        scanScalars(listing, candidates);
        refsToStrings(listing, candidates);
        for (long a : FOLLOW) candidates.add(toAddr(a));
        // expand one caller level so the chain up to cal_init is visible
        TreeSet<Address> callers = new TreeSet<Address>();
        for (Address e : candidates) {
            Function f = fm.getFunctionAt(e);
            if (f == null) continue;
            for (Function c : f.getCallingFunctions(monitor))
                callers.add(c.getEntryPoint());
        }
        candidates.addAll(callers);
        decompileCandidates(fm, candidates, 45);

        String report = "/home/chanz22/Documents/GitHub/exynos9825-payloads/build/dmc_trace_report.txt";
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

    /* Samsung logs printf("%s: ...", __func__, ...). A function that references
     * exactly one identifier-looking string is very likely named by it. Only
     * rename default FUN_ names, and only on a unique identifier, to be safe. */
    private void recoverFuncNames(Listing listing) throws Exception {
        Map<Address, Set<String>> perFunc = new HashMap<Address, Set<String>>();
        Map<Address, Function> fobj = new HashMap<Address, Function>();
        DataIterator it = listing.getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            Object v = d.getValue();
            if (!(v instanceof String)) continue;
            String s = (String) v;
            if (!IDENT.matcher(s).matches()) continue;
            Reference[] refs = getReferencesTo(d.getAddress());
            for (Reference r : refs) {
                Function f = getFunctionContaining(r.getFromAddress());
                if (f == null) continue;
                Address e = f.getEntryPoint();
                Set<String> set = perFunc.get(e);
                if (set == null) { set = new HashSet<String>(); perFunc.put(e, set); }
                set.add(s);
                fobj.put(e, f);
            }
        }
        int named = 0;
        for (Map.Entry<Address, Set<String>> en : perFunc.entrySet()) {
            if (en.getValue().size() != 1) continue;
            Function f = fobj.get(en.getKey());
            String nm = f.getName();
            if (nm.startsWith("FUN_") || nm.startsWith("thunk_FUN_")) {
                try {
                    f.setName(en.getValue().iterator().next(), SourceType.USER_DEFINED);
                    named++;
                } catch (Exception ignore) { }
            }
        }
        out("[names] recovered " + named + " unique __func__-based names");
    }

    private void refsToTargets(Set<Address> candidates) {
        out("");
        out("=== references to DMC/ECT data tables ===");
        for (int i = 0; i < TARGET_ADDR.length; i++) {
            Address a = toAddr(TARGET_ADDR[i]);
            Reference[] refs = getReferencesTo(a);
            out(String.format("0x%06x  %s  (%d refs)",
                    TARGET_ADDR[i], TARGET_DESC[i], refs.length));
            for (Reference r : refs) {
                Function f = getFunctionContaining(r.getFromAddress());
                out("    from " + r.getFromAddress() + "  " + r.getReferenceType()
                        + "  -> " + fsig(f));
                if (f != null) candidates.add(f.getEntryPoint());
            }
        }
    }

    private void scanScalars(Listing listing, Set<Address> candidates) {
        out("");
        out("=== instruction scalars matching NEWTIME keys / rates ===");
        Map<Long, List<Address>> hits = new HashMap<Long, List<Address>>();
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            int n = ins.getNumOperands();
            for (int op = 0; op < n; op++) {
                for (Object obj : ins.getOpObjects(op)) {
                    if (obj instanceof Scalar) {
                        long v = ((Scalar) obj).getUnsignedValue();
                        if (SCALARS.containsKey(v)) {
                            List<Address> l = hits.get(v);
                            if (l == null) { l = new ArrayList<Address>(); hits.put(v, l); }
                            l.add(ins.getAddress());
                        }
                    }
                }
            }
        }
        for (Map.Entry<Long, String> e : SCALARS.entrySet()) {
            List<Address> locs = hits.get(e.getKey());
            int c = (locs == null) ? 0 : locs.size();
            out(String.format("0x%x (%s): %d", e.getKey(), e.getValue(), c));
            if (locs != null) {
                for (int i = 0; i < locs.size() && i < 12; i++) {
                    Function f = getFunctionContaining(locs.get(i));
                    out("    at " + locs.get(i) + "  " + fsig(f));
                    if (f != null) candidates.add(f.getEntryPoint());
                }
            }
        }
    }

    private void refsToStrings(Listing listing, Set<Address> candidates) {
        out("");
        out("=== referrers of DMC/ECT strings ===");
        DataIterator it = listing.getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            Object v = d.getValue();
            if (!(v instanceof String)) continue;
            String s = (String) v;
            for (String needle : STRINGS) {
                if (s.contains(needle)) {
                    Reference[] refs = getReferencesTo(d.getAddress());
                    for (Reference r : refs) {
                        Function f = getFunctionContaining(r.getFromAddress());
                        out(String.format("%-22s @%s <- %s",
                                "\"" + needle + "\"", d.getAddress(), fsig(f)));
                        if (f != null) candidates.add(f.getEntryPoint());
                    }
                    break;
                }
            }
        }
    }

    private void decompileCandidates(FunctionManager fm, Set<Address> candidates,
                                     int limit) {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        out("");
        out("=== candidate functions (" + candidates.size() + ") ===");
        int shown = 0;
        for (Address e : candidates) {
            if (shown >= limit) {
                out("... (" + (candidates.size() - shown)
                        + " more candidates not decompiled; raise limit)");
                break;
            }
            Function f = fm.getFunctionAt(e);
            if (f == null) continue;
            shown++;
            out("");
            out("----------------------------------------------------------------");
            out("FUNC " + fsig(f));
            out("  callers: " + names(f.getCallingFunctions(monitor)));
            out("  callees: " + names(f.getCalledFunctions(monitor)));
            try {
                DecompileResults res = di.decompileFunction(f, 90, monitor);
                if (res != null && res.decompileCompleted()) {
                    out(res.getDecompiledFunction().getC());
                } else {
                    out("  // decompile did not complete");
                }
            } catch (Exception ex) {
                out("  // decompile error: " + ex);
            }
        }
        di.dispose();
    }

    private String names(Set<Function> fs) {
        if (fs == null || fs.isEmpty()) return "(none)";
        TreeSet<String> s = new TreeSet<String>();
        for (Function f : fs) s.add(f.getName());
        StringBuilder b = new StringBuilder();
        for (String n : s) { if (b.length() > 0) b.append(", "); b.append(n); }
        return b.toString();
    }
}
