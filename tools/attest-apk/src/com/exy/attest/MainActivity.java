package com.exy.attest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * Pulls a hardware-backed key attestation and prints the RootOfTrust: the
 * four fields a remote verifier would read. This shows what the TEE ATTESTS,
 * which is the answer to "did force-green reach the secure world" -- the
 * bootloader analysis only showed what u-boot SENDS.
 */
public class MainActivity extends Activity {
    static final String TAG = "ROOTOFTRUST";
    // Samsung/AOSP key attestation extension.
    static final String OID = "1.3.6.1.4.1.11129.2.1.17";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        ScrollView sv = new ScrollView(this);
        TextView tv = new TextView(this);
        tv.setTextSize(13);
        tv.setPadding(28, 28, 28, 28);
        tv.setTextIsSelectable(true);
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
        sv.addView(tv);
        setContentView(sv);

        StringBuilder o = new StringBuilder();
        try { run(o); }
        catch (Throwable t) { o.append("\nERROR: ").append(t).append('\n'); Log.e(TAG, "fail", t); }
        String s = o.toString();
        tv.setText(s);
        for (String line : s.split("\n")) Log.i(TAG, line);
    }

    void run(StringBuilder o) throws Exception {
        String alias = "rot_test_" + System.currentTimeMillis();
        byte[] challenge = "exynos9825-rootoftrust".getBytes();

        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(spec);
        kpg.generateKeyPair();

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Certificate[] chain = ks.getCertificateChain(alias);
        o.append("attestation chain length: ").append(chain == null ? 0 : chain.length).append('\n');
        if (chain == null || chain.length == 0) {
            o.append("no chain -> no hardware attestation\n"); return;
        }
        for (int i = 0; i < chain.length; i++)
            o.append("  cert[").append(i).append("] ")
             .append(((X509Certificate) chain[i]).getSubjectX500Principal()).append('\n');

        byte[] ext = ((X509Certificate) chain[0]).getExtensionValue(OID);
        if (ext == null) { o.append("\nno attestation extension in leaf cert\n"); return; }

        byte[] kd = Der.unwrapOctet(ext);          // KeyDescription SEQUENCE
        o.append('\n');
        reportKeyDescription(kd, o);
        reportRootOfTrust(kd, o);

        try { ks.deleteEntry(alias); } catch (Exception ignore) {}
    }

    void reportKeyDescription(byte[] kd, StringBuilder o) {
        try {
            Der.TLV seq = Der.read(kd, 0);         // outer SEQUENCE
            int p = seq.contentStart;
            Der.TLV ver = Der.read(kd, p);          // attestationVersion INTEGER
            p = ver.next;
            Der.TLV sl = Der.read(kd, p);           // attestationSecurityLevel ENUMERATED
            int lvl = kd[sl.contentStart] & 0xff;
            o.append("attestationVersion : ").append(Der.intOf(kd, ver)).append('\n');
            o.append("securityLevel      : ").append(lvl)
             .append(lvl == 0 ? " (Software)" : lvl == 1 ? " (TrustedEnvironment)" : lvl == 2 ? " (StrongBox)" : "")
             .append('\n');
        } catch (Exception e) { o.append("(could not read KeyDescription head: ").append(e).append(")\n"); }
    }

    void reportRootOfTrust(byte[] kd, StringBuilder o) {
        // RootOfTrust is tagged [704] explicit: 0xBF 0x85 0x40.
        int at = -1;
        for (int i = 0; i + 3 < kd.length; i++)
            if ((kd[i] & 0xff) == 0xBF && (kd[i + 1] & 0xff) == 0x85 && (kd[i + 2] & 0xff) == 0x40) { at = i; break; }
        o.append('\n');
        if (at < 0) { o.append("RootOfTrust [704] not present (not in teeEnforced)\n"); return; }

        Der.TLV outer = Der.read(kd, at);           // the [704] wrapper
        Der.TLV rot = Der.read(kd, outer.contentStart);  // inner SEQUENCE
        int p = rot.contentStart;

        Der.TLV vbKey = Der.read(kd, p); p = vbKey.next;        // verifiedBootKey OCTET STRING
        Der.TLV locked = Der.read(kd, p); p = locked.next;      // deviceLocked BOOLEAN
        Der.TLV state = Der.read(kd, p); p = state.next;        // verifiedBootState ENUMERATED
        Der.TLV vbHash = (p < rot.next) ? Der.read(kd, p) : null; // verifiedBootHash OCTET STRING

        boolean dl = (kd[locked.contentStart] & 0xff) != 0;
        int st = kd[state.contentStart] & 0xff;
        String stName = st == 0 ? "Verified" : st == 1 ? "SelfSigned" : st == 2 ? "Unverified" : st == 3 ? "Failed" : "?";

        o.append("=== RootOfTrust (what the TEE attests) ===\n");
        o.append("deviceLocked       : ").append(dl).append('\n');
        o.append("verifiedBootState  : ").append(st).append(" (").append(stName).append(")\n");
        o.append("verifiedBootKey     : ").append(Der.hex(kd, vbKey.contentStart, vbKey.contentLen)).append('\n');
        o.append("verifiedBootHash    : ").append(vbHash == null ? "(absent)" : Der.hex(kd, vbHash.contentStart, vbHash.contentLen)).append('\n');
    }
}
