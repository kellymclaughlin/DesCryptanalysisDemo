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
 *
 * DesCryptanalysis.java
 *
 * Created on March 15, 2006, 8:33 PM
 *
 */

import java.util.ArrayList;
import java.util.Random;
import java.util.StringTokenizer;

/**
 * This class implements the cryptanalysis of DES for 6 rounds. The cryptanalysis process is done using two
 * characteristics. Each characteristic can be used to suggest with high probability the key bits of the
 * round key of the last encryption round. For two input plaintext pairs to be a part of a characteristic,
 * the xor of the two values must be equals to the plaintext value specified by the characteristic. The two
 * characteristic values used in this implementation are 0x4008000004000000 and 0x0020000800000400. Each
 * characteristic suggest 30 bits of the key (5 SBoxes * 6 bits), but three of the SBox inputs overlap
 * giving a net result of 42 key bits.
 *
 * @author Kelly McLaughlin
 */
public class DesCryptanalysis {
    private static final int NUMBER_OF_ROUNDS = 6;
    public static final int DEFAULT_NUMBER_OF_TUPLES = 20000;
    private int[][] sbox1DifferenceDistribution;
    private int[][] sbox2DifferenceDistribution;
    private int[][] sbox3DifferenceDistribution;
    private int[][] sbox4DifferenceDistribution;
    private int[][] sbox5DifferenceDistribution;
    private int[][] sbox6DifferenceDistribution;
    private int[][] sbox7DifferenceDistribution;
    private int[][] sbox8DifferenceDistribution;
    private DES des;
    public ExpansionPermutation ep;
    private long key;
    private int numberOfCharOneTuples;
    private int numberOfCharTwoTuples;
    private int charOneSbox2Keybits;
    private int charOneSbox5Keybits;
    private int charOneSbox6Keybits;
    private int charOneSbox7Keybits;
    private int charOneSbox8Keybits;
    private int charTwoSbox1Keybits;
    private int charTwoSbox2Keybits;
    private int charTwoSbox4Keybits;
    private int charTwoSbox5Keybits;
    private int charTwoSbox6Keybits;

    /** Creates a new instance of DesCryptanalysis */
    public DesCryptanalysis() {

        numberOfCharOneTuples = 0;
        numberOfCharTwoTuples = 0;

        des = new DES();
        ep = new ExpansionPermutation();
    }

    /**
     * This method searches through every possible value for the 14 key bits
     * that could not be recovered from the cryptanalysis. Once the correct key is
     * found, it is returned and the search is halted.
     *
     * @param input ArrayList containing input from the user interface that
     * specifies plaintext/ciphertext pairs for the two characteristics used
     * in the cryptanalysis.
     */
    public long determineKey(ArrayList input)
    {

        ArrayList[] characteristicTupleArrays = createTuples(input);

        int[] charOneKeyBits = determineCharOneKeyBits(characteristicTupleArrays[0]);
        int[] charTwoKeyBits = determineCharTwoKeyBits(characteristicTupleArrays[1]);

        int counter = 0;
        boolean keyFound = false;
        int sbox3Bits = 0;
        long testKey = 0L;
        long expandedKeyBits;

        while (counter < 16384 && !keyFound)
        {
            sbox3Bits = (counter & 0x3f00) >> 8;

            long knownKeyBits = (((long)charTwoKeyBits[0]) << 42L) + (((long)charTwoKeyBits[1]) << 36L) + (((long)sbox3Bits) << 30) + (charTwoKeyBits[2] << 24) + (charTwoKeyBits[3] << 18) +
                    (charOneKeyBits[2] << 12) + (charOneKeyBits[3] << 6) + charOneKeyBits[4];
            long unshuffledKeyBits = new KeySchedule().getInversePC2Val(knownKeyBits, counter);
            int cVal = (int)((unshuffledKeyBits & 0xfffffff0000000L)>>28L);
            int dVal = (int)((unshuffledKeyBits & 0x0000000fffffffL));

            //Rotate the bits to the original positions
            int lowerBits = cVal & 0x3ff;
            int rotatedCVal = (cVal >> 10) | (lowerBits << 18);
            lowerBits = dVal & 0x3ff;
            int rotatedDVal = (dVal >> 10) | (lowerBits << 18);
            long orderedKeyBits = ((long)rotatedCVal << 28L) | rotatedDVal;

            unshuffledKeyBits = new KeySchedule().getInversePC1Val(orderedKeyBits);
            expandedKeyBits = expandKeyBits(unshuffledKeyBits);

            //Add in the bits for the test key
            testKey = addParityKeyBits(expandedKeyBits);

            //Check the possible key against one of the previously encrypted tuples
            long testCipherText = getDes().decrypt(((Tuple)characteristicTupleArrays[0].get(0)).getY1(), testKey, DesCryptanalysis.NUMBER_OF_ROUNDS);

            if (testCipherText == ((Tuple)characteristicTupleArrays[0].get(0)).getX1())
            {
                keyFound = true;
            }

            counter++;
        }

        return testKey;

    }

    private long getKey()
    {
        return key;
    }

    public void setKey(long key)
    {
        this.key = key;
    }

    public DES getDes()
    {
        return des;
    }

    /**
     * This method determines the key bits for the first characteristic
     * used in the crypanalytic attack. It returns an array of five integers
     * representing the key bits determined as the output of SBoxes 2, 5, 6, 7,
     * and 8.
     *
     * @param tuples ArrayList representing the input plaintext/ciphertext
     * tuples for the first characteristic.
     */
    public int[] determineCharOneKeyBits(ArrayList tuples)
    {
        ExpansionPermutation exp = new ExpansionPermutation();
        SBox sbox = new SBox();
        int s2Input, s5Input, s6Input, s7Input, s8Input;
        int s2Output, s5Output, s6Output, s7Output, s8Output;
        int s2ValidOutput, s5ValidOutput, s6ValidOutput, s7ValidOutput, s8ValidOutput;
        int retval = 0;
        long e1, e2, esum;
        int lPrime, sBoxOutput, sBoxInput, e1Input, e2Input;
        int k2Prime, k5Prime, k6Prime, k7Prime, k8Prime;

        int s2MaxIndex = -1;
        int s5MaxIndex = -1;
        int s6MaxIndex = -1;
        int s7MaxIndex = -1;
        int s8MaxIndex = -1;
        int s2MaxVal = -1;
        int s5MaxVal = -1;
        int s6MaxVal = -1;
        int s7MaxVal = -1;
        int s8MaxVal = -1;

        //Initialize the key frequency arrays for each SBox of interest
        int [] S2KeyCount = new int[64];
        int [] S5KeyCount = new int[64];
        int [] S6KeyCount = new int[64];
        int [] S7KeyCount = new int[64];
        int [] S8KeyCount = new int[64];

        for (int i=0; i<64; i++)
        {
            S2KeyCount[i] = 0;
            S5KeyCount[i] = 0;
            S6KeyCount[i] = 0;
            S7KeyCount[i] = 0;
            S8KeyCount[i] = 0;
        }

        for (int i=0; i<tuples.size(); i++)
        {
            //Get possible input for the last round of SBoxes
            e1 = exp.E((long)(((Tuple)(tuples.get(i))).getY1()));
            e2 = exp.E((long)(((Tuple)(tuples.get(i))).getY2()));
            esum = e1 ^ e2;

            //Determine the valid output from the SBoxes to determine which Tuples are right
            lPrime = (int)((((Tuple)(tuples.get(i))).getY1() & 0xffffffff00000000L) >> 32) ^ (int)((((Tuple)(tuples.get(i))).getY2() & 0xffffffff00000000L) >> 32);
            sBoxOutput = exp.InverseP(lPrime ^ 0x04000000);

            //For each SBox, check the possible keys
            for (int j=0; j<64; j++)
            {
                //Check Sbox2
                e1Input = (int)((e1 & (0x3fL << 36))>>36);
                e2Input = (int)((e2 & (0x3fL << 36))>>36);

                s2Input = (int)((esum & (0x3fL << 36))>>36);

                k2Prime = s2Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox2Output = sbox.getSboxValue(e1Input ^ k2Prime, 2);
                int e2SBox2Output = sbox.getSboxValue(e2Input ^ k2Prime, 2);

                if ((e1SBox2Output ^ e2SBox2Output) == ((sBoxOutput & 0xf000000)>>24))
                {
                        S2KeyCount[j]++;
                }


                //Check Sbox5
                e1Input = (int)((e1 & (0x3fL << 18))>>18);
                e2Input = (int)((e2 & (0x3fL << 18))>>18);

                s5Input = (int)((esum & (0x3fL << 18))>>18);

                k5Prime = s5Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox5Output = sbox.getSboxValue(e1Input ^ k5Prime, 5);
                int e2SBox5Output = sbox.getSboxValue(e2Input ^ k5Prime, 5);

                if ((e1SBox5Output ^ e2SBox5Output) == ((sBoxOutput & 0xf000)>>12))
                {
                    //Increment key counter
                    S5KeyCount[j]++;
                }


                //Check Sbox6
                e1Input = (int)((e1 & (0x3fL << 12))>>12);
                e2Input = (int)((e2 & (0x3fL << 12))>>12);

                s6Input = (int)((esum & (0x3fL << 12))>>12);

                k6Prime = s6Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox6Output = sbox.getSboxValue(e1Input ^ k6Prime, 6);
                int e2SBox6Output = sbox.getSboxValue(e2Input ^ k6Prime, 6);

                if ((e1SBox6Output ^ e2SBox6Output) == ((sBoxOutput & 0xf00)>>8))
                {
                    //Increment key counter
                    S6KeyCount[j]++;
                }


                //Check Sbox7
                e1Input = (int)((e1 & (0x3fL << 6))>>6);
                e2Input = (int)((e2 & (0x3fL << 6))>>6);

                s7Input = (int)((esum & (0x3fL << 6))>>6);

                k7Prime = s7Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox7Output = sbox.getSboxValue(e1Input ^ k7Prime, 7);
                int e2SBox7Output = sbox.getSboxValue(e2Input ^ k7Prime, 7);

                if ((e1SBox7Output ^ e2SBox7Output) == ((sBoxOutput & 0xf0)>>4))
                {
                    //Increment key counter
                    S7KeyCount[j]++;
                }


                //Check Sbox8
                e1Input = (int)((e1 & (0x3fL)));
                e2Input = (int)((e2 & (0x3fL)));

                s8Input = (int)((esum & (0x3fL)));

                k8Prime = s8Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox8Output = sbox.getSboxValue(e1Input ^ k8Prime, 8);
                int e2SBox8Output = sbox.getSboxValue(e2Input ^ k8Prime, 8);


                if ((e1SBox8Output ^ e2SBox8Output) == ((sBoxOutput & 0xf)))
                {
                    //Increment key counter
                    S8KeyCount[j]++;

                }
            }
        }


        for (int i=0; i<64; i++)
        {

            if (S2KeyCount[i] > s2MaxVal)
            {
                s2MaxIndex = i;
                s2MaxVal = S2KeyCount[i];
            }
            if (S5KeyCount[i] > s5MaxVal)
            {
                s5MaxIndex = i;
                s5MaxVal = S5KeyCount[i];
            }
            if (S6KeyCount[i] > s6MaxVal)
            {
                s6MaxIndex = i;
                s6MaxVal = S6KeyCount[i];
            }
            if (S7KeyCount[i] > s7MaxVal)
            {
                s7MaxIndex = i;
                s7MaxVal = S7KeyCount[i];
            }
            if (S8KeyCount[i] > s8MaxVal)
            {
                s8MaxIndex = i;
                s8MaxVal = S8KeyCount[i];
            }
        }

        charOneSbox2Keybits = s2MaxIndex;
        charOneSbox5Keybits = s5MaxIndex;
        charOneSbox6Keybits = s6MaxIndex;
        charOneSbox7Keybits = s7MaxIndex;
        charOneSbox8Keybits = s8MaxIndex;

        return new int[]{s2MaxIndex, s5MaxIndex, s6MaxIndex, s7MaxIndex, s8MaxIndex};
    }

    /**
     * This method determines the key bits for the second characteristic
     * used in the crypanalytic attack. It returns an array of five integers
     * representing the key bits determined as the output of SBoxes 1, 2, 4, 5,
     * and 6.
     *
     * @param tuples ArrayList representing the input plaintext/ciphertext
     * tuples for the second characteristic.
     */
    public int[] determineCharTwoKeyBits(ArrayList tuples)
    {
        ExpansionPermutation exp = new ExpansionPermutation();
        SBox sbox = new SBox();
        int s1Input, s2Input, s4Input, s5Input, s6Input;
        int s1Output, s2Output, s4Output, s5Output, s6Output;
        int s1ValidOutput, s2ValidOutput, s4ValidOutput, s5ValidOutput, s6ValidOutput;
        int retval = 0;
        long e1, e2, esum;
        int lPrime, sBoxOutput, sBoxInput, e1Input, e2Input;
        int k1Prime, k2Prime, k4Prime, k5Prime, k6Prime;

        int s1MaxIndex = -1;
        int s2MaxIndex = -1;
        int s4MaxIndex = -1;
        int s5MaxIndex = -1;
        int s6MaxIndex = -1;
        int s1MaxVal = -1;
        int s2MaxVal = -1;
        int s4MaxVal = -1;
        int s5MaxVal = -1;
        int s6MaxVal = -1;

        int [] S1KeyCount = new int[64];
        int [] S2KeyCount = new int[64];
        int [] S4KeyCount = new int[64];
        int [] S5KeyCount = new int[64];
        int [] S6KeyCount = new int[64];

        for (int i=0; i<64; i++)
        {
            S1KeyCount[i] = 0;
            S2KeyCount[i] = 0;
            S4KeyCount[i] = 0;
            S5KeyCount[i] = 0;
            S6KeyCount[i] = 0;
        }

        for (int i=0; i<tuples.size(); i++)
        {
            //Get possible input for the last round of SBoxes
            e1 = exp.E((long)(((Tuple)(tuples.get(i))).getY1()));
            e2 = exp.E((long)(((Tuple)(tuples.get(i))).getY2()));
            esum = e1 ^ e2;

            //Determine the valid output from the SBoxes to determine which Tuples are right
            lPrime = (int)((((Tuple)(tuples.get(i))).getY1() & 0xffffffff00000000L) >> 32) ^ (int)((((Tuple)(tuples.get(i))).getY2() & 0xffffffff00000000L) >> 32);
            sBoxOutput = exp.InverseP(lPrime ^ 0x00000400);

            //For each SBox, check the possible keys
            for (int j=0; j<64; j++)
            {
                //Check Sbox1
                e1Input = (int)((e1 & (0x3fL << 42))>>42);
                e2Input = (int)((e2 & (0x3fL << 42))>>42);

                s1Input = (int)((esum & (0x3fL << 42))>>42);

                k1Prime = s1Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox1Output = sbox.getSboxValue(e1Input ^ k1Prime, 1);
                int e2SBox1Output = sbox.getSboxValue(e2Input ^ k1Prime, 1);

                if ((e1SBox1Output ^ e2SBox1Output) == ((sBoxOutput & 0xf0000000)>>28))
                {
                    S1KeyCount[j]++;
                }


                //Check Sbox2
                e1Input = (int)((e1 & (0x3fL << 36))>>36);
                e2Input = (int)((e2 & (0x3fL << 36))>>36);

                s2Input = (int)((esum & (0x3fL << 36))>>36);

                k2Prime = s2Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox2Output = sbox.getSboxValue(e1Input ^ k2Prime, 2);
                int e2SBox2Output = sbox.getSboxValue(e2Input ^ k2Prime, 2);

                if ((e1SBox2Output ^ e2SBox2Output) == ((sBoxOutput & 0xf000000)>>24))
                {
                        S2KeyCount[j]++;
                }

                //Check Sbox4
                e1Input = (int)((e1 & (0x3fL << 24))>>24);
                e2Input = (int)((e2 & (0x3fL << 24))>>24);

                s4Input = (int)((esum & (0x3fL << 24))>>24);

                k4Prime = s4Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox4Output = sbox.getSboxValue(e1Input ^ k4Prime, 4);
                int e2SBox4Output = sbox.getSboxValue(e2Input ^ k4Prime, 4);

                if ((e1SBox4Output ^ e2SBox4Output) == ((sBoxOutput & 0xf0000)>>16))
                {
                    //Increment key counter
                    S4KeyCount[j]++;
                }

                //Check Sbox5
                e1Input = (int)((e1 & (0x3fL << 18))>>18);
                e2Input = (int)((e2 & (0x3fL << 18))>>18);

                s5Input = (int)((esum & (0x3fL << 18))>>18);

                k5Prime = s5Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox5Output = sbox.getSboxValue(e1Input ^ k5Prime, 5);
                int e2SBox5Output = sbox.getSboxValue(e2Input ^ k5Prime, 5);

                if ((e1SBox5Output ^ e2SBox5Output) == ((sBoxOutput & 0xf000)>>12))
                {
                    //Increment key counter
                    S5KeyCount[j]++;
                }


                //Check Sbox6
                e1Input = (int)((e1 & (0x3fL << 12))>>12);
                e2Input = (int)((e2 & (0x3fL << 12))>>12);

                s6Input = (int)((esum & (0x3fL << 12))>>12);

                k6Prime = s6Input ^ j;

                //Calculate SBox out for each input XORed with kPrime
                int e1SBox6Output = sbox.getSboxValue(e1Input ^ k6Prime, 6);
                int e2SBox6Output = sbox.getSboxValue(e2Input ^ k6Prime, 6);

                if ((e1SBox6Output ^ e2SBox6Output) == ((sBoxOutput & 0xf00)>>8))
                {
                    //Increment key counter
                    S6KeyCount[j]++;
                }
            }
        }

        for (int i=0; i<64; i++)
        {
            if (S1KeyCount[i] > s1MaxVal)
            {
                s1MaxIndex = i;
                s1MaxVal = S1KeyCount[i];
            }
            if (S2KeyCount[i] > s2MaxVal)
            {
                s2MaxIndex = i;
                s2MaxVal = S2KeyCount[i];
            }
            if (S4KeyCount[i] > s4MaxVal)
            {
                s4MaxIndex = i;
                s4MaxVal = S4KeyCount[i];
            }
            if (S5KeyCount[i] > s5MaxVal)
            {
                s5MaxIndex = i;
                s5MaxVal = S5KeyCount[i];
            }
            if (S6KeyCount[i] > s6MaxVal)
            {
                s6MaxIndex = i;
                s6MaxVal = S6KeyCount[i];
            }
        }

        charTwoSbox1Keybits = s1MaxIndex;
        charTwoSbox2Keybits = s2MaxIndex;
        charTwoSbox4Keybits = s4MaxIndex;
        charTwoSbox5Keybits = s5MaxIndex;
        charTwoSbox6Keybits = s6MaxIndex;

        return new int[]{s1MaxIndex, s2MaxIndex, s4MaxIndex, s5MaxIndex, s6MaxIndex};
    }

    /**
     * This method receives an input ArrayList with plaintext/ciphertext tuples
     * for both of the characteristics used in the cryptanalysis. It separates
     * input for each characterstic returns a separate ArrayList for each
     * characteristic.
     *
     * @param input ArrayList containing input from the user interface that
     * specifies plaintext/ciphertext pairs for the two characteristics used
     * in the cryptanalysis.
     */
    public ArrayList[] createTuples(ArrayList input)
    {
        ArrayList charOneTuples = new ArrayList<Tuple>();
        ArrayList charTwoTuples = new ArrayList<Tuple>();
        StringTokenizer strtok1 = null;

        int inputSize = input.size();
        int inputCounter = 0;
        String inputLine = new String("");
        boolean characteristicDataSeparatorFound = false;

        while (inputCounter < inputSize && !characteristicDataSeparatorFound)
        {
            inputLine = (String)input.get(inputCounter);

            if (inputLine.startsWith("--------------------"))
            {
                characteristicDataSeparatorFound = true;
            }
            else
            {
                strtok1 = new StringTokenizer(inputLine.trim(), ";");
                Tuple tuple = new Tuple();

                if (strtok1.hasMoreTokens())
                {
                    tuple.setX1(Long.parseLong(strtok1.nextToken()));
                }
                if (strtok1.hasMoreTokens())
                {
                    tuple.setX2(Long.parseLong(strtok1.nextToken()));
                }
                if (strtok1.hasMoreTokens())
                {
                    tuple.setY1(Long.parseLong(strtok1.nextToken()));
                }
                if (strtok1.hasMoreTokens())
                {
                    tuple.setY2(Long.parseLong(strtok1.nextToken()));
                }

                charOneTuples.add(tuple);
            }

            inputCounter++;
        }

        while (inputCounter < inputSize)
        {
            inputLine = (String)input.get(inputCounter);

            strtok1 = new StringTokenizer(inputLine.trim(), ";");
            Tuple tuple = new Tuple();

            if (strtok1.hasMoreTokens())
            {
                tuple.setX1(Long.parseLong(strtok1.nextToken()));
            }
            if (strtok1.hasMoreTokens())
            {
                tuple.setX2(Long.parseLong(strtok1.nextToken()));
            }
            if (strtok1.hasMoreTokens())
            {
                tuple.setY1(Long.parseLong(strtok1.nextToken()));
            }
            if (strtok1.hasMoreTokens())
            {
                tuple.setY2(Long.parseLong(strtok1.nextToken()));
            }

            inputCounter++;

            charTwoTuples.add(tuple);
        }

        numberOfCharOneTuples = charOneTuples.size();
        numberOfCharTwoTuples = charTwoTuples.size();

        return new ArrayList[] { charOneTuples, charTwoTuples };
    }

    /**
     * This method generates a random DES key
     */
    public long generateKey()
    {
        Random rng = new Random(System.nanoTime());
        long keyVal;

        keyVal= rng.nextLong();

        return(addParityKeyBits(keyVal & 0xffffffffffffffL));
    }

    /**
     * This method generates random pairs of plaintext/ciphertext pairs for
     * each of the two characteristics and returns them as a single ArrayList
     * separated by a line containing only dashes.
     */
    public ArrayList generateInputPairs()
    {
        ArrayList inputPairs = new ArrayList<String>();
        ArrayList charOneTuples = getCharOneTuples(DEFAULT_NUMBER_OF_TUPLES);
        ArrayList charTwoTuples = getCharTwoTuples(DEFAULT_NUMBER_OF_TUPLES);

        numberOfCharOneTuples = charOneTuples.size();
        numberOfCharTwoTuples = charTwoTuples.size();

        for (int i=0; i<numberOfCharOneTuples; i++)
        {
            String inputLine = new String("");

            Tuple tuple = (Tuple)charOneTuples.get(i);

            inputLine += Long.toString(tuple.getX1()) + ";" + Long.toString(tuple.getX2()) + ";" + Long.toString(tuple.getY1()) + ";" + Long.toString(tuple.getY2());

            inputLine += "\r\n";

            inputPairs.add(inputLine);
        }

        inputPairs.add("--------------------\r\n");

        for (int i=0; i<numberOfCharTwoTuples; i++)
        {
            String inputLine = new String("");

            Tuple tuple = (Tuple)charTwoTuples.get(i);

            inputLine += Long.toString(tuple.getX1()) + ";" + Long.toString(tuple.getX2()) + ";" + Long.toString(tuple.getY1()) + ";" + Long.toString(tuple.getY2());

            if (i != numberOfCharTwoTuples-1)
            {
                inputLine += "\r\n";
            }

            inputPairs.add(inputLine);
        }

        return inputPairs;
    }

    /**
     * This method returns the number of plaintext/ciphertext pairs that were
     * determined to be "right pairs" from the original set of generated pairs
     * for the first characteristic.
     */
    public int getNumberOfCharOneTuples()
    {
        return numberOfCharOneTuples;
    }

    /**
     * This method returns the number of plaintext/ciphertext pairs that were
     * determined to be "right pairs" from the original set of generated pairs
     * for the second characteristic.
     */
    public int getNumberOfCharTwoTuples()
    {
        return numberOfCharTwoTuples;
    }

    /**
     * This method generates 20000 plaintext pairs whose value when XORed
     * together is equal to 0x4008000004000000. Each of the plaintext pairs
     * is encrypted and then tested to determine if they are a "right pair".
     * A "right pair" is found when the XOR of the output from the encryption
     * of each value in the first and third encryption rounds is equal to
     * 0x40080000. If a pair does not meet this criteria, it is discarded. The
     * "right pairs" are returned as an ArrayList of Tuples.
     *
     * @param numberOfTuples int value indicating the number of plaintext pairs
     * to generate and filter.
     */
    public ArrayList getCharOneTuples(int numberOfTuples)
    {
        ArrayList tupleArray = new ArrayList<Tuple>(1);
        Random rng = new Random(System.nanoTime());
        long pt;
        int x1FirstRoundFOutput;
        int x1ThirdRoundFOutput;
        int x2FirstRoundFOutput;
        int x2ThirdRoundFOutput;

        for (int i=0; i< numberOfTuples; i++)
        {
            pt = rng.nextLong();
            Tuple tuple = new Tuple();
            tuple.setX1(pt);
            tuple.setX2(pt ^ 0x4008000004000000L);

            tuple.setY1(des.encrypt(tuple.getX1(), key, NUMBER_OF_ROUNDS));
            x1FirstRoundFOutput = des.getFirstRoundFOutput();
            x1ThirdRoundFOutput = des.getThirdRoundFOutput();
            int fourOut1 = des.getFourthRoundFOutput();
            tuple.setY2(des.encrypt(tuple.getX2(), key, NUMBER_OF_ROUNDS));
            x2FirstRoundFOutput = des.getFirstRoundFOutput();
            x2ThirdRoundFOutput = des.getThirdRoundFOutput();
            int fourOut2 = des.getFourthRoundFOutput();

            if (((x1FirstRoundFOutput ^ x2FirstRoundFOutput) == 1074266112) && ((x1ThirdRoundFOutput ^ x2ThirdRoundFOutput) == 1074266112))
            {
                tupleArray.add(tuple);;
            }
        }

        return tupleArray;
    }

    /**
     * This method generates 20000 plaintext pairs whose value when XORed
     * together is equal to 0x0020000800000400. Each of the plaintext pairs
     * is encrypted and then tested to determine if they are a "right pair".
     * A "right pair" is found when the XOR of the output from the encryption
     * of each value in the first and third encryption rounds is equal to
     * 0x00200008. If a pair does not meet this criteria, it is discarded. The
     * "right pairs" are returned as an ArrayList of Tuples.
     *
     * @param numberOfTuples int value indicating the number of plaintext pairs
     * to generate and filter.
     */
    public ArrayList getCharTwoTuples(int numberOfTuples)
    {
        ArrayList tupleArray = new ArrayList<Tuple>(1);
        Random rng = new Random(System.nanoTime());
        long pt;
        int x1FirstRoundFOutput;
        int x1ThirdRoundFOutput;
        int x2FirstRoundFOutput;
        int x2ThirdRoundFOutput;

        for (int i=0; i< numberOfTuples; i++)
        {
            pt = rng.nextLong();
            Tuple tuple = new Tuple();
            tuple.setX1(pt);
            tuple.setX2(pt ^ 0x0020000800000400L);

            tuple.setY1(des.encrypt(tuple.getX1(), key, NUMBER_OF_ROUNDS));
            x1FirstRoundFOutput = des.getFirstRoundFOutput();
            x1ThirdRoundFOutput = des.getThirdRoundFOutput();
            int fourOut1 = des.getFourthRoundFOutput();
            tuple.setY2(des.encrypt(tuple.getX2(), key, NUMBER_OF_ROUNDS));
            x2FirstRoundFOutput = des.getFirstRoundFOutput();
            x2ThirdRoundFOutput = des.getThirdRoundFOutput();
            int fourOut2 = des.getFourthRoundFOutput();

            if (((x1FirstRoundFOutput ^ x2FirstRoundFOutput) == 2097160) && ((x1ThirdRoundFOutput ^ x2ThirdRoundFOutput) == 2097160))
            {
                tupleArray.add(tuple);
            }
        }

        return tupleArray;
    }

    private int[][] getSboxDifferenceDistribution(int sboxNumber)
    {
        int[][] distribution = new int[64][16];
        int outputXor1, outputXor2;
        SBox sbox = new SBox();

        //Initialize distribution to all zeroes
        for (int i=0; i<64; i++)
        {
            for (int j=0; j<16; j++)
            {
                distribution[i][j] = 0;
            }
        }

        for (int i=0; i<64; i++)
        {
            outputXor1 = sbox.getSboxValue(i, sboxNumber);
            for (int j=0; j<64; j++)
            {
                outputXor2 = sbox.getSboxValue(j, sboxNumber);
                distribution[i^j][outputXor1^outputXor2]++;
            }
        }
        return distribution;
    }

    private int[][] getSboxDifferenceDistributionReference(int sboxNumber)
    {
        int dist[][];

        switch(sboxNumber)
        {
            case 1:
                dist = sbox1DifferenceDistribution;
                break;
            case 2:
                dist = sbox2DifferenceDistribution;
                break;
            case 3:
                dist = sbox3DifferenceDistribution;
                break;
            case 4:
                dist = sbox4DifferenceDistribution;
                break;
            case 5:
                dist = sbox5DifferenceDistribution;
                break;
            case 6:
                dist = sbox6DifferenceDistribution;
                break;
            case 7:
                dist = sbox7DifferenceDistribution;
                break;
            case 8:
                dist = sbox8DifferenceDistribution;
                break;
            default:
                dist = null;
        };

        return dist;
    }

    public void printSboxDifferenceDistribution(int sboxNumber)
    {
        int [][] distribution = getSboxDifferenceDistributionReference(sboxNumber);

        for (int i=0; i<64; i++)
        {
            System.out.print(i + ": ");
            for (int j=0; j<16; j++)
            {
                System.out.print(distribution[i][j] + " ");
            }
            System.out.println("");
        }
    }

    /**
     * This method expands the 56 bit key to 64 bits leaving zero for
     * the parity bits.
     *
     * @param keyBits long value representing the 56 bit key value
     */
    public long expandKeyBits(long keyBits)
    {
        long retval = 0L;

        retval += ((keyBits & (0x7fL << 49)) >> 49 ) << 57;
        retval += ((keyBits & (0x7fL << 42)) >> 42 ) << 49;
        retval += ((keyBits & (0x7fL << 35)) >> 35 ) << 41;
        retval += ((keyBits & (0x7fL << 28)) >> 28 ) << 33;
        retval += ((keyBits & (0x7fL << 21)) >> 21 ) << 25;
        retval += ((keyBits & (0x7fL << 14)) >> 14 ) << 17;
        retval += ((keyBits & (0x7fL << 7)) >> 7 ) << 9;
        retval += ((keyBits & 0x7fL) << 1);

        return retval;
    }

    //This method inserts the test bits into the proper bits positions in the test key
    public long insertTestKeyBits(long testKey, int testBits)
    {
        long retVal = testKey;

        retVal |= (((long)(testBits & 0x2000)) << 50);
        retVal |= (((long)(testBits & 0x1000)) << 45);
        retVal |= (((long)(testBits & 0x800)) << 44);
        retVal |= (((long)(testBits & 0x400)) << 36);
        retVal |= (((long)(testBits & 0x200)) << 36);
        retVal |= (((long)(testBits & 0x100)) << 31);
        retVal |= (((long)(testBits & 0x80)) << 29);
        retVal |= (((long)(testBits & 0x40)) << 25);
        retVal |= (((long)(testBits & 0x20)) << 23);
        retVal |= (((long)(testBits & 0x10)) << 23);
        retVal |= (((long)(testBits & 0x8)) << 18);
        retVal |= (((long)(testBits & 0x4)) << 11);
        retVal |= (((long)(testBits & 0x2)) << 7);
        retVal |= (((long)(testBits & 0x1)) << 4);

        return retVal;
    }

    /**
     * This method determines and sets the proper parity bits for the key.
     * DES keys are required to have odd parity and the parity bit is the
     * least significant byte of each byte of the key.
     *
     * @param keyBits long value representing the key value without the
     * parity bits added.
     */
    public long addParityKeyBits(long keyBits)
    {
        long retval = keyBits;
        int tmpVal;
        int oneCount;


        tmpVal = (int)((keyBits & (0x7fL << 57)) >> 57);
        oneCount = 0;
        for (int i=0; i<7; i++)
        {
            if (((1<<i) & tmpVal) == (1<<i))
            {
                oneCount++;
            }
        }

        if ((oneCount % 2) == 0)
        {
            retval |= (1L<<56L);
        }
        else if ((keyBits & (1L<<56L)) == (1L<<56L))
        {
            retval ^= (1L<<56L);
        }

        tmpVal = (int)((keyBits & (0x7fL << 49)) >> 49);
        oneCount = 0;
        for (int i=0; i<7; i++)
        {
            if (((1<<i) & tmpVal) == (1<<i))
            {
                oneCount++;
            }
        }

        if ((oneCount % 2) == 0)
        {
            retval |= (1L<<48L);
        }
        else if ((keyBits & (1L<<48L)) == (1L<<48L))
        {
            retval ^= (1L<<48L);
        }

        tmpVal = (int)((keyBits & (0x7fL << 41L)) >> 41L);
        oneCount = 0;
        for (int i=0; i<7; i++)
        {
            if (((1<<i) & tmpVal) == (1<<i))
            {
                oneCount++;
            }
        }

        if ((oneCount % 2) == 0)
        {
            retval |= (1L<<40L);
        }
        else if ((keyBits & (1L<<40L)) == (1L<<40L))
        {
            retval ^= (1L<<40L);
        }

        tmpVal = (int)((keyBits & (0x7fL << 33L)) >> 33L);
        oneCount = 0;
        for (int i=0; i<7; i++)
        {
            if (((1<<i) & tmpVal) == (1<<i))
            {
                oneCount++;
            }
        }

        if ((oneCount % 2) == 0)
        {
            retval |= (1L<<32L);
        }
        else if ((keyBits & (1L<<32L)) == (1L<<32L))
        {
            retval ^= (1L<<32L);
        }

        tmpVal = (int)((keyBits & (0x7fL << 25L)) >> 25L);
        oneCount = 0;
        for (int i=0; i<7; i++)
        {
            if (((1<<i) & tmpVal) == (1<<i))
            {
                oneCount++;
            }
        }

        if ((oneCount % 2) == 0)
        {
            retval |= (1L<<24L);
        }
        else if ((keyBits & (1L<<24L)) == (1L<<24L))
        {
            retval ^= (1L<<24L);
        }

        tmpVal = (int)((keyBits & (0x7fL << 17)) >> 17);
        oneCount = 0;
        for (int i=0; i<7; i++)
        {
            if (((1<<i) & tmpVal) == (1<<i))
            {
                oneCount++;
            }
        }

        if ((oneCount % 2) == 0)
        {
            retval |= (1L<<16);
        }
        else if ((keyBits & (1L<<16L)) == (1L<<16L))
        {
            retval ^= (1L<<16L);
        }

        tmpVal = (int)((keyBits & (0x7fL << 9)) >> 9);
        oneCount = 0;
        for (int i=0; i<7; i++)
        {
            if (((1<<i) & tmpVal) == (1<<i))
            {
                oneCount++;
            }
        }

        if ((oneCount % 2) == 0)
        {
            retval |= (1L<<8);
        }
        else if ((keyBits & (1L<<8L)) == (1L<<8L))
        {
            retval ^= (1L<<8L);
        }

        tmpVal = (int)((keyBits & (0x7fL << 1)) >> 1);
        oneCount = 0;
        for (int i=0; i<7; i++)
        {
            if (((1<<i) & tmpVal) == (1<<i))
            {
                oneCount++;
            }
        }

        if ((oneCount % 2) == 0)
        {
            retval |= 1L;
        }
        else if ((keyBits & 1L) == 1L)
        {
            retval ^= 1;
        }

        return retval;
    }

    /**
     * This method returns the key bits as ouptut from SBox 2 determined by the
     * first characteristic.
     */
    public int getCharOneS2KeyBits()
    {
        return charOneSbox2Keybits;
    }

    /**
     * This method returns the key bits as ouptut from SBox 5 determined by the
     * first characteristic.
     */
    public int getCharOneS5KeyBits()
    {
        return charOneSbox5Keybits;
    }

    /**
     * This method returns the key bits as ouptut from SBox 6 determined by the
     * first characteristic.
     */
    public int getCharOneS6KeyBits()
    {
        return charOneSbox6Keybits;
    }

    /**
     * This method returns the key bits as ouptut from SBox 7 determined by the
     * first characteristic.
     */
    public int getCharOneS7KeyBits()
    {
        return charOneSbox7Keybits;
    }

    /**
     * This method returns the key bits as ouptut from SBox 8 determined by the
     * first characteristic.
     */
    public int getCharOneS8KeyBits()
    {
        return charOneSbox8Keybits;
    }

    /**
     * This method returns the key bits as ouptut from SBox 1 determined by the
     * second characteristic.
     */
    public int getCharTwoS1KeyBits()
    {
        return charTwoSbox1Keybits;
    }

    /**
     * This method returns the key bits as ouptut from SBox 2 determined by the
     * second characteristic.
     */
    public int getCharTwoS2KeyBits()
    {
        return charTwoSbox2Keybits;
    }

    /**
     * This method returns the key bits as ouptut from SBox 4 determined by the
     * second characteristic.
     */
    public int getCharTwoS4KeyBits()
    {
        return charTwoSbox4Keybits;
    }

    /**
     * This method returns the key bits as ouptut from SBox 5 determined by the
     * second characteristic.
     */
    public int getCharTwoS5KeyBits()
    {
        return charTwoSbox5Keybits;
    }

    /**
     * This method returns the key bits as ouptut from SBox 6 determined by the
     * second characteristic.
     */
    public int getCharTwoS6KeyBits()
    {
        return charTwoSbox6Keybits;
    }
}