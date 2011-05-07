/*
 * This file is provided to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * ExpansionPermutation.java
 *
 * Created on March 10, 2006, 4:56 PM
 *
 */

/**
 * This class implements the InitialPermutation, Expansion and Permutation
 * functions that are part of each round of the DES encryption process. It also
 * includes the function to perform an inverse Expansion and inverse
 * Permutation.
 *
 * @author Kelly McLaughlin
 */
public class ExpansionPermutation {

    private int[] InitialPermutation = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    private int[] InverseInitialPermutation = {
      40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25
    };

    private int [] Expansion = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };

    private int [] InverseExpansion = {
        2, 3, 4, 5,
        6, 9, 10, 11,
        12, 15, 16, 17,
        18, 21, 22, 23,
        24, 27, 28, 29,
        30, 33, 34, 35,
        36, 39, 40, 41,
        42, 45, 46, 47
    };

    /**
     * This method expands the input from 32 bits to 48 bits based on the
     * expansion described in the DES algorithm.
     *
     * @param input long value specifying a 32 bit value to be expanded to 48 bits
     */
    public long E(long input) {
        long eVal = 0;
        int bitpos = 47;

        for (int i=0; i<48; i++)
        {
            if ((input & (1L << 32-Expansion[i])) == (1L << 32-Expansion[i]))
            {
                eVal |= 1L << bitpos;
            }
            bitpos--;
        }

        return eVal;
    }

    /**
     * This method reduces the input from 48 bits to 32 bits based on the
     * expansion described in the DES algorithm.
     *
     * @param input long value specifying a 32 bit value to be expanded to 56 bits
     */
    public long InverseE(long input) {
        long eVal = 0;
        int bitpos = 31;

        for (int i=0; i<32; i++)
        {
            if ((input & (1L << 48-InverseExpansion[i])) == (1L << 48-InverseExpansion[i]))
            {
                eVal |= 1L << bitpos;
            }
            bitpos--;
        }

        return eVal;
    }

    private int[] Permutation = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    };

    private int[] InversePermutation = {
        9, 17, 23, 31,
        13, 28, 2, 18,
        24, 16, 30, 6,
        26, 20, 10, 1,
        8, 14, 25, 3,
        4, 29, 11, 19,
        32, 12, 22, 7,
        5, 27, 15, 21
    };


    /** Creates a new instance of ExpansionPermutation */
    public ExpansionPermutation() {
    }

    /**
     * This method performs the initial permutation as described by the DES algorithm on the
     * plaintext input.
     *
     * @param plaintext long value specifying a plaintext value
     */
    public long IP(long plaintext) {
        long ipVal = 0;
        int bitpos = 63;

        for (int i=0; i<64; i++)
        {
            if ((plaintext & (1L << 64-InitialPermutation[i])) == (1L << 64-InitialPermutation[i]))
            {
                ipVal |= 1L << bitpos;
            }
            //ipVal |= ((plaintext & (1L << 64-InitialPermutation[i])) >> 64-InitialPermutation[i]) << bitpos;
            bitpos--;
        }

        return ipVal;
    }

    /**
     * This method performs the inverse initial permutation as described by the
     * DES algorithm on the ciphertext input.
     *
     * @param ciphertext long value specifying a ciphertext value
     */
    public long InverseIP(long ciphertext) {
        long ipVal = 0;
        int bitpos = 63;

        for (int i=0; i<64; i++)
        {
            if ((ciphertext & (1L << 64-InverseInitialPermutation[i])) == (1L << 64-InverseInitialPermutation[i]))
            {
                ipVal |= 1L << bitpos;
            }
            bitpos--;
        }

        return ipVal;
    }

    /**
     * This method performs the permutation as described by the DES algorithm on the
     * input.
     *
     * @param input int value specifying a value for permutation
     */
    public int P(int input) {
        int pVal = 0;
        int bitpos = 31;

        for (int i=0; i<32; i++)
        {
            if ((input & (1L << 32-Permutation[i])) == (1L << 32-Permutation[i]))
            {
                pVal |= 1L << bitpos;
            }
            bitpos--;
        }

        return pVal;
    }

    /**
     * This method performs the inverse of the permutation described by the DES algorithm on the
     * input.
     *
     * @param input int value specifying a value for inverse permutation
     */
    public int InverseP(int input) {
        int pVal = 0;
        int bitpos = 31;

        for (int i=0; i<32; i++)
        {
            if ((input & (1L << 32-InversePermutation[i])) == (1L << 32-InversePermutation[i]))
            {
                pVal |= 1L << bitpos;
            }
            bitpos--;
        }

        return pVal;
    }
}
