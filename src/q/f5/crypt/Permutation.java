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

import java.util.concurrent.atomic.AtomicReference;

public class Permutation {

    static AtomicReference<int[]> ic = new AtomicReference<>(null);
    int[] shuffled; // shuffled sequence

    // The constructor of class Permutation creates a shuffled
    // sequence of the integers 0 ... (size-1).
    public Permutation(final int size, final F5Random random) {
        int i, randomIndex, tmp;
        this.shuffled = new int[size];

        int[] cached = ic.get();
        if (cached == null) {
            this.shuffled = new int[size];
            // To create the shuffled sequence, we initialise an array
            // with the integers 0 ... (size-1).
            for (i = 0; i < size; i++) {
                // initialise with �size� integers
                this.shuffled[i] = i;
            }
            ic.set(this.shuffled.clone());
        } else {
            this.shuffled = cached.clone();
        }

        int maxRandom = size; // set number of entries to shuffle
        for (i = 0; i < size; i++) { // shuffle entries
            randomIndex = random.getNextValue(maxRandom--);
            tmp = this.shuffled[randomIndex];
            this.shuffled[randomIndex] = this.shuffled[maxRandom];
            this.shuffled[maxRandom] = tmp;
        }
        /*
        for (int j = 0; j < 10; j++) {
            System.out.printf("%d = %d\n", j, this.shuffled[j]);
        }
        */
    }

    // get value #i from the shuffled sequence
    public int getShuffled(final int i) {
        return this.shuffled[i];
    }
}
