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
package q.f5.crypt;

import sun.security.provider.SecureRandom;

public class F5Random {
    private SecureRandom random = null;

    private byte[] b = null;

    public F5Random(final byte[] password) {
        this.random = new SecureRandom();
        this.random.engineSetSeed(password);
        this.b = new byte[1];
        /*
        System.out.print("initial rands ");
        for (int i = 0; i < 20; i++) {
            System.out.printf("%02x", this.getNextByte()&0xff);
        }
        System.out.println("");
        */
        this.random = new SecureRandom();
        this.random.engineSetSeed(password);
        this.b = new byte[1];
    }

    // get a random byte
    public int getNextByte() {
        this.random.engineNextBytes(this.b);
//        System.out.printf("rand %02x\n",(int)this.b[0] & 0xff);
        return this.b[0];
    }

    // get a random integer 0 ... (maxValue-1)
    public int getNextValue(final int maxValue) {
        int retVal = getNextByte() | getNextByte() << 8 | getNextByte() << 16 | getNextByte() << 24;
        retVal %= maxValue;
        if (retVal < 0) {
            retVal += maxValue;
        }
        return retVal;
    }
}
