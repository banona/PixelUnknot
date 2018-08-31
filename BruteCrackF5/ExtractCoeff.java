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
import java.io.*;
import java.lang.*;
import java_parts.*;

public class ExtractCoeff {
 
    public static void main(String[] args) {
        
        if( args.length < 2){
            System.out.print("JPEG Coefficent Extractor\n");
            System.out.print("Usage: java JpegExtract input.jpeg output.coeff\n");
            System.exit(0);
        }
        
        try{
            File fi = new File(args[0]);
            FileInputStream fin = new FileInputStream(args[0]);
            FileOutputStream fout = new FileOutputStream(args[1]);
            //DataOutputStream dos = new DataOutputStream(fout);
                
            byte[] jpegFile = new byte[(int)fi.length()];
        
            fin.read(jpegFile);
            fin.close();
        
            HuffmanDecode hd = new HuffmanDecode(jpegFile);
            int[] coeff = hd.decode();
        
            for(int i = 0; i < coeff.length; i++){
                // Output data is little endin short ints
                short s = (short)coeff[i];
                fout.write(s);
                fout.write(s>>8);
            }
            fout.close();
        }
        catch(IOException e) {
            System.err.print("File error\n");
            System.exit(1);
        }
        
        
    }   
}
