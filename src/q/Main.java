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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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

    public static int extract(int[] coeff, String mPassword) {
        Extract e = new Extract();
        OutputStream ostream = new ByteArrayOutputStream();
        try {
            e.extract(coeff, ostream, mPassword);
        } catch (IOException e1) {
            e1.printStackTrace();
        }
//        e.extract(coeff, ostream, extractF5Seed(mPassword));
        String mMessage = ostream.toString();
        // System.out.println("message is " + mMessage);

        if (mMessage != null && mMessage.indexOf(Constants.PASSWORD_SENTINEL) == 0) {
            String secret_message = mMessage.substring(Constants.PASSWORD_SENTINEL.length());
            System.out.println("!!!!!!!!!!! PARTIAL MATCH - " + mPassword);
            System.out.println("!!!!!!!!!!! PARTIAL MATCH - " + mPassword);
            System.out.println("!!!!!!!!!!! PARTIAL MATCH - " + mPassword);
            System.out.println("!!!!!!!!!!! PARTIAL MATCH - " + mPassword);
            System.exit(0);
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

        final File f = new File(args[0]);
        final FileInputStream fis = new FileInputStream(f);
        byte[] carrier; // carrier data
        carrier = new byte[(int) f.length()];
        fis.read(carrier);
        final HuffmanDecode hd = new HuffmanDecode(carrier);
        System.out.println("Huffman decoding starts");
        final int[] coeff = hd.decode(); // dct values

        Path filePath = Paths.get(args[1]);
        Files.readAllLines(filePath, StandardCharsets.ISO_8859_1)
                .parallelStream()
                .forEach(line -> {
                    for (int j = 0; j<line.length() - 2; j++) {
                        String l = line.substring(j);
                        // System.out.println("trying " + l);
                        int res = extract(coeff, l);
                        if (res == 1) {
                            System.exit(1);
                        }
                    }
                });
    }
}
