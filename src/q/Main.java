/* /////////////// DISCLAIMER/////////////////////////////////
   This software is provided by the author and
   contributors ``as is'' and any express or implied
   warranties, including, but not limited to, the
   implied warranties of merchantability and
   fitness for a particular purpose are dis-
   claimed. In no event shall the author or con-
   tributors be liable for any direct, indirect,
   incidental, special, exemplary, or consequen-
   tial damages (including, but not limited to,
   procurement of substitute goods or services;
   loss of use, data, or profits; or business
   interruption) however caused and on any
   theory of liability, whether in contract,
   strict liability, or tort (including negligence
   or otherwise) arising in any way out of the use
   of this software, even if advised of the poss-
   ibility of such damage.
//////////////////////////////////////////////////////*/
package q;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import q.f5.Extract;
import q.f5.ortega.HuffmanDecode;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicLong;

import static java.lang.System.exit;

public class Main {

    public static String DecryptWithPassword(String password, byte[] iv, byte[] message, byte[] salt) {
        String new_message = null;

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret_key = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, secret_key, new IvParameterSpec(iv));

            new_message = new String(cipher.doFinal(message));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new_message;
    }

    private static String extractPassword(String from_password) {
        return from_password.substring(0, from_password.length()/3);
    }

    private static String extractPasswordSalt(String from_password) {
        return from_password.substring(from_password.length()/3, (from_password.length()/3)*2);
    }

    private static String extractF5Seed(String from_password) {
        return from_password.substring((from_password.length()/3)*2);
    }

    public static class Constants {
        public final static String PASSWORD_SENTINEL = "----* PK v 1.0 REQUIRES PASSWORD ----*";
    }

    public static int extract(int[] coeff, String mPassword, int max_len) {
        // System.out.println("trying " + mPassword);
        Extract e = new Extract();
        OutputStream ostream = new ByteArrayOutputStream();
        try {
            // e.extract(coeff, ostream, extractF5Seed(mPassword));
            // TEST - FOR BRUTE FORCING LAST 1/3
            e.extract(coeff, ostream, mPassword, max_len);
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        String mMessage = ostream.toString();
        // System.out.println("message is " + mMessage);

        if (mMessage != null && mMessage.indexOf(Constants.PASSWORD_SENTINEL) == 0) {
            String secret_message = mMessage.substring(Constants.PASSWORD_SENTINEL.length());
            System.out.println("!!!!!!!!!!! PARTIAL MATCH - " + mPassword);
            System.out.println("!!!!!!!!!!! PARTIAL MATCH - " + mPassword);
            System.out.println("!!!!!!!!!!! PARTIAL MATCH - " + mPassword);
            System.out.println("!!!!!!!!!!! PARTIAL MATCH - " + mPassword);
            // TEST - FOR BRUTE FORCING LAST 1/3
            Runtime.getRuntime().halt(1);
            int idx = secret_message.indexOf("\n");

            String mMsg = secret_message.substring(idx + 1, secret_message.length());
            String mIv = secret_message.substring(0, idx);

            byte[] message = new byte[0];
            byte[] iv = new byte[0];
            try {
                message = Base64.decode(mMsg);
                iv = Base64.decode(mIv);
            } catch (Base64DecodingException e1) {
                e1.printStackTrace();
            }

            String sm = DecryptWithPassword(extractPassword(mPassword), iv, message, extractPasswordSalt(mPassword).getBytes());
            if (sm != null) {
                mMessage = sm;
                System.out.println("CORRECT PASSWORD " + mPassword);
                System.out.println("==============================");
                System.out.println(mMessage);
                System.out.println("==============================");
                return 1;
            } else {
                // Wrong password
                System.out.println("decryption error with password " + mPassword);
            }
        } else {
            //System.out.println("bad password [" + mPassword + "] ");
        }
        return 0;
    }

    public static void main(String[] args) throws IOException, InterruptedException, ExecutionException {
        Security.addProvider(new BouncyCastleProvider());
        // -----------------------
        // useful code to extract coeff files for a directory
        // -----------------------
        /*
        File[] files = new File("matches").listFiles();
        for (File file : files) {
            if (file.isFile() && !file.getAbsolutePath().endsWith(".coeff")) {
                File cf = new File( file.getAbsolutePath() + ".coeff");
                if (!cf.exists()) {
                    System.out.println("extracting coeff for " + file.getName());
                    final int[] coeff = loadCoeff(file);
                    // save coeff file for CUDA crack
                    save_coeff(file.getAbsolutePath(), coeff);
                }
            }
        }
        exit(0);
        */

        if (args.length < 2) {
            System.out.println("Usage: PixelUnknot Q4example.jpg passwords.txt");
        }

        String path = args[0];
        System.out.println("untie " + path);
        final File f = new File(path);
        final int[] coeff = loadCoeff(f);
        // save coeff file for CUDA crack
        save_coeff(path, coeff);

        int max_msg_len = 0;
        for (int i = 0; i < coeff.length; i++)
        if ((i % 64 != 0) & (coeff[i] != 0))
            max_msg_len++;

        System.out.println("Max theoretical message length: " + max_msg_len);

        final long startTime = System.currentTimeMillis();
        AtomicLong lineCount = new AtomicLong(0);
        Timer t = new Timer();
        t.schedule(new TimerTask() {
            @Override
            public void run() {
                long estimatedTime = (System.currentTimeMillis() - startTime) / 1000L;
                System.out.println("count: " + lineCount.get() + " elapsed: " + estimatedTime + "s = rate: " + (lineCount.get() / estimatedTime) + " pw/s");
            }
        }, 60000, 60000);

        Path filePath = Paths.get(args[1]);
        final int max_len = max_msg_len;
        Files.readAllLines(filePath, StandardCharsets.ISO_8859_1)
                .parallelStream()
                .forEach(line -> {
                    trySuffixes(coeff, lineCount, line, max_len);
                    StringBuilder rev = new StringBuilder();
                    rev.append(line);
                    trySuffixes(coeff, lineCount, rev.reverse().toString(), max_len);
                });
        Runtime.getRuntime().halt(1);
    }

    private static int[] loadCoeff(File f) throws IOException {
        final FileInputStream fis = new FileInputStream(f);
        byte[] carrier; // carrier data
        carrier = new byte[(int) f.length()];
        fis.read(carrier);
        final HuffmanDecode hd = new HuffmanDecode(carrier);
        System.out.println("Huffman decoding starts");
        return hd.decode();
    }

    private static void save_coeff(String arg, int[] coeff) throws IOException {
        FileOutputStream fout = new FileOutputStream(arg + ".coeff");
        for(int i = 0; i < coeff.length; i++){
            // Output data is little endin short ints
            short s = (short)coeff[i];
            fout.write(s);
            fout.write(s>>8);
        }
        fout.close();
    }

    private static void trySuffixes(int[] coeff, AtomicLong lineCount, String line, int max_len) {
        // System.out.println("trying " + line);
        int res = extract(coeff, line, max_len);
        if (res == 1) {
            exit(1);
        }
        lineCount.incrementAndGet();
        for (int j = 1; j<line.length() - 4; j++) {
           String l = line.substring(j);
           // System.out.println("trying " + l);
            res = extract(coeff, l, max_len);
            if (res == 1) {
                exit(1);
            }
            lineCount.incrementAndGet();
        }
    }
}
