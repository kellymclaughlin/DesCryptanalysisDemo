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
 * DES.java
 *
 * Created on March 10, 2006, 4:46 PM
 *
 */

/**
 * This class implments the DES encryption and decryption with the user specifying the
 * input plaintext or ciphertext, the encryption/decryption key, and the number of
 * encryption rounds used.
 *
 * @author Kelly McLaughlin
 */
public class DES {
    private SBox sbox;
    private ExpansionPermutation expansionPermutation;
    private KeySchedule keySchedule;
    private int firstRoundFOutput;
    private int thirdRoundFOutput;
    private int fourthRoundFOutput;
    private int sboxOut;

    /** Creates a new instance of DES */
    public DES() {
        sbox = new SBox();
        expansionPermutation = new ExpansionPermutation();
        keySchedule = new KeySchedule();
    }

    /**
     ** Performs DES encryption to encrypt the specified plaintext using the
     * specified key and the given number of decryption rounds.
     *
     * @param plaintext long value specifying the plaintext to encrypt
     * @param key long value specifying the key to use to encrypt the plaintext
     * @param rounds int value specifying the number of rounds to use in encrypting the plaintext
     */
    public long encrypt(long plaintext, long key, int rounds)
    {
        int lVal, rVal, prevLVal, prevRVal;
        long expandedVal, sboxInput, ciphertext;
        int sboxOutput;


        //Get the number of rounds keys needed for this operation
        long [] roundKeys = keySchedule.getEncryptionRoundKeys(key, rounds);

        //Perform the initial permutation
        //NOTE: Uncomment this section to have the encryption function perform
        //      the initial permutation.
        /*
        long ipPlaintext = expansionPermutation.IP(plaintext);

        int L0 = (int)((ipPlaintext & 0xffffffff00000000L) >> 32);
        int R0 = (int)(ipPlaintext & 0xffffffff);
        */

        //NOTE: Comment out the next two lines to have the encryption function perform
        //      the initial permutation.
        int L0 = (int)((plaintext & 0xffffffff00000000L) >> 32);
        int R0 = (int)(plaintext & 0xffffffff);

        lVal = L0;
        rVal = R0;

        for (int i=0; i<rounds; i++)
        {
            prevLVal = lVal;
            prevRVal = rVal;

            lVal = prevRVal;

            //Perform the expansion
            expandedVal = expansionPermutation.E(prevRVal);

            //Xor the expanded value with the round key
            sboxInput = expandedVal ^ roundKeys[i];

            //Get the output for the SBoxes for the input for this round
            sboxOutput = 0;
            int sval;
            for (int j=0; j<8; j++)
            {
                sval = (int)((sboxInput & (0x3fL << (j*6))) >> (j*6));
                sboxOutput |= ( sbox.getSboxValue((int)((sboxInput & (0x3fL << (j*6))) >> (j*6)), 8-j) ) << (j*4);
            }

            //Get the output of the f function which is not just the permutation,
            //P, of the Sbox output
            int fVal = expansionPermutation.P(sboxOutput);

            //This block of if statements is just for the cryptanalysis
            //computations. It has no functional impact on the encryption.
            if (i == 0)
            {
                firstRoundFOutput = fVal;
            }
            else if (i == 2)
            {
                thirdRoundFOutput = fVal;
            }
            else if (i == 3)
            {
                fourthRoundFOutput = fVal;
            }
            else if (i == rounds-1)
            {
                sboxOut = sboxOutput;
            }

            //Set the new Right side value to the xor of
            //the previous Left side value and the output
            //of the f function
            if (i != rounds-1)
            {
                rVal = prevLVal ^ fVal;
            }
            else
            {
                lVal = prevLVal ^ fVal;
            }
        }

        //Exchange the final blocks
        //Note: For crytanalsis, we do not want to exchange the final blocks,
        //but to use the function for normal encryption, uncomment the following
        //line.
        //ciphertext = (((long)rVal) << 32) + (lVal & 0x00000000ffffffffL);

        //Note: For crytanalsis, we do not want to exchange the final blocks,
        //but to use the function for normal encryption, comment out the
        //following line.
        ciphertext = (((long)lVal) << 32) + (rVal & 0x00000000ffffffffL);

        //Perform the inverse initial permutation
        //NOTE: Uncomment the following line to have the encryption function perform
        //      the initial permutation.
        //long ipCiphertext = expansionPermutation.InverseIP(ciphertext);

        //NOTE: Comment out the following line if using the initial permutation.
        return ciphertext;

        //NOTE: Uncomment the following line if using the initial permutation.
        //return ipCiphertext;
    }

    /**
     * Performs DES decryption to decrypt the specified ciphertext using the
     * specified key and the given number of decryption rounds.
     *
     * @param ciphertext long value specifying the ciphertext to decrypt
     * @param key long value specifying the key to use to encrypt the plaintext
     * @param rounds int value specifying the number of rounds to use in encrypting the plaintext
     */
    public long decrypt(long ciphertext, long key, int rounds)
    {
        int lVal, rVal, prevLVal, prevRVal;
        long expandedVal, sboxInput, plaintext;
        int sboxOutput;


        //Get the number of rounds keys needed for this operation
        long [] roundKeys = keySchedule.getDecryptionRoundKeys(key, rounds);

        //Perform the initial permutation
        //NOTE: Uncomment this section to have the encryption function perform
        //      the initial permutation.
        /*
        long ipCiphertext = expansionPermutation.IP(ciphertext);

        int L0 = (int)((ipCiphertext & 0xffffffff00000000L) >> 32);
        int R0 = (int)(ipCiphertext & 0xffffffff);
        */

        int L0 = (int)((ciphertext & 0xffffffff00000000L) >> 32);
        int R0 = (int)(ciphertext & 0xffffffff);

        lVal = L0;
        rVal = R0;

        for (int i=0; i<rounds; i++)
        {
            prevLVal = lVal;
            prevRVal = rVal;

            lVal = prevRVal;

            //Perform the expansion
            expandedVal = expansionPermutation.E(prevRVal);

            //Xor the expanded value with the round key
            sboxInput = expandedVal ^ roundKeys[i];

            sboxOutput = 0;

            //Get the output for the SBoxes for the input for this round
            for (int j=0; j<8; j++)
            {
                sboxOutput |= ( sbox.getSboxValue((int)((sboxInput & (0x3fL << (j*6))) >> (j*6)), 8-j) ) << (j*4);
            }

            //Get the output of the f function which is not just the permutation,
            //P, of the Sbox output
            int fVal = expansionPermutation.P(sboxOutput);

            //Set the new Right side value to the xor of
            //the previous Left side value and the output
            //of the f function
            if (i != rounds-1)
            {
                rVal = prevLVal ^ fVal;
            }
            else
            {
                lVal = prevLVal ^ fVal;
            }
        }

        //Exchange the final blocks
        //Note: For crytanalsis, we do not want to exchange the final blocks,
        //but to use the function for normal encryption, uncomment the following
        //line.
        //plaintext = (((long)rVal) << 32) + (lVal & 0x00000000ffffffffL);

        //Note: For crytanalsis, we do not want to exchange the final blocks,
        //but to use the function for normal encryption, comment out the
        //following line.
        plaintext = (((long)lVal) << 32) + (rVal & 0x00000000ffffffffL);

        //Perform the inverse initial permutation
        //NOTE: Uncomment the following line to have the encryption function perform
        //      the initial permutation.
        //long ipPlaintext = expansionPermutation.InverseIP(plaintext);

        //NOTE: Comment out the following line if using the initial permutation.
        return plaintext;

        //NOTE: Uncomment the following line if using the initial permutation.
        //return ipPlaintext;
    }

    /**
     * This method returns an int value indicating the output from the DES f
     * function in the third round of encryption. This method is for use in the
     * cryptanalysis process.
     */
    public int getThirdRoundFOutput()
    {
        return thirdRoundFOutput;
    }

    /**
     * This method returns an int value indicating the output from the DES f
     * function in the first round of encryption. This method is for use in the
     * cryptanalysis process.
     */
    public int getFirstRoundFOutput()
    {
        return firstRoundFOutput;
    }

    /**
     * This method returns an int value indicating the output from the DES f
     * function in the fourth round of encryption. This method is for use in the
     * cryptanalysis process.
     */
    public int getFourthRoundFOutput()
    {
        return firstRoundFOutput;
    }
}

