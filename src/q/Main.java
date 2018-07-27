package q;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import q.f5.Extract;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.spec.KeySpec;

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

    static String readFile(String path, Charset encoding)
            throws IOException
    {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }

    public static void extract(String inFileName, String outFileName, String mPassword) throws IOException, Base64DecodingException {
        final File f = new File(inFileName);
        final FileInputStream fis = new FileInputStream(f);
        final FileOutputStream fos = new FileOutputStream(new File(outFileName));
        Extract.extract(fis, (int) f.length(), fos, mPassword);

        String mMessage = readFile(outFileName, Charset.defaultCharset());
        // System.out.println("message is " + mMessage);

        if (mMessage != null && mMessage.indexOf(Constants.PASSWORD_SENTINEL) == 0) {
            String secret_message = mMessage.substring(Constants.PASSWORD_SENTINEL.length());

            int idx = secret_message.indexOf("\n");

            String mMsg = secret_message.substring(idx + 1, secret_message.length());
            String mIv = secret_message.substring(0, idx);

            byte[] message = Base64.decode(mMsg);
            byte[] iv =  Base64.decode(mIv);

            String sm = DecryptWithPassword(extractPassword(mPassword), iv, message, extractPasswordSalt(mPassword).getBytes());
            if (sm != null) {
                mMessage = sm;
                System.out.println("CORRECT PASSWORD " + mPassword);
                System.out.println("==============================");
                System.out.println(mMessage);
                System.out.println("==============================");
            } else {
                // Wrong password
                System.out.println("decryption error with password " + mPassword);
            }
        } else {
            System.out.println("wrong password " + mPassword);
        }
    }

    public static void main(String[] args) throws IOException, Base64DecodingException {
        Security.addProvider(new BouncyCastleProvider());
        try (BufferedReader br = new BufferedReader(new FileReader(args[1]))) {
            String line;
            while ((line = br.readLine()) != null) {
                extract(args[0], "tmp.txt", line);
            }
        }
    }
}
