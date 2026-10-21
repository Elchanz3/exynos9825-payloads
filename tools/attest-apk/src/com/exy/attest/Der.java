package com.exy.attest;

/** A minimal DER walker: just enough to find and read the fields we print. */
final class Der {
    static final class TLV {
        int tagStart, contentStart, contentLen, next;
    }

    /** Read one TLV at offset, resolving short and long length forms. */
    static TLV read(byte[] d, int off) {
        TLV t = new TLV();
        t.tagStart = off;
        int p = off + 1;
        // multi-byte (high-tag-number) tags: low 5 bits all set
        if ((d[off] & 0x1f) == 0x1f) { while ((d[p] & 0x80) != 0) p++; p++; }
        int len = d[p++] & 0xff;
        if ((len & 0x80) != 0) {
            int n = len & 0x7f, v = 0;
            for (int i = 0; i < n; i++) v = (v << 8) | (d[p++] & 0xff);
            len = v;
        }
        t.contentStart = p;
        t.contentLen = len;
        t.next = p + len;
        return t;
    }

    /** Unwrap a DER OCTET STRING (what getExtensionValue returns around the body). */
    static byte[] unwrapOctet(byte[] d) {
        TLV t = read(d, 0);
        byte[] out = new byte[t.contentLen];
        System.arraycopy(d, t.contentStart, out, 0, t.contentLen);
        return out;
    }

    static long intOf(byte[] d, TLV t) {
        long v = 0;
        for (int i = 0; i < t.contentLen; i++) v = (v << 8) | (d[t.contentStart + i] & 0xff);
        return v;
    }

    static String hex(byte[] d, int off, int len) {
        if (len == 0) return "(empty)";
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < len; i++) s.append(String.format("%02x", d[off + i] & 0xff));
        return s.toString();
    }

    private Der() {}
}
