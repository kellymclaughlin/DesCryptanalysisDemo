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
 * SBox.java
 *
 * Created on March 10, 2006, 4:55 PM
 *
 */

import java.util.ArrayList;

/**
 * This class provides the functionality to determine the output of a particular
 * SBox given an input or the possible input values of an SBox given the output.
 *
 * @author Kelly McLaughlin
 */
public class SBox {

    private byte[][] S1 = { {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                           {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                           {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                           {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };

    private byte[][] S2 = { {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                           {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                           {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                           {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };

    private byte[][] S3 = { {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                           {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                           {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                           {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };

    private byte[][] S4 = { {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                         {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                         {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                         {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };

    private byte[][] S5 = { {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                           {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                           {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                           {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };

    private byte[][] S6 = { {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                           {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                           {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                           {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };

    private byte[][] S7 = { {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                         {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                         {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                         {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };

    private byte[][] S8 = { {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                              {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                              {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                              {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };


    /** Creates a new instance of SBox */
    public SBox() {
    }

    /**
     * Returns a byte indicating the output from the specified SBox
     * given the input.
     *
     * @param input int value specifying the input to the SBox
     * @param sboxIndex int value specifying and index from 1-8
     *   indicating which SBox the input should go to.
     */
    public byte getSboxValue(int input, int sboxIndex)
    {
        int row = ((input & 32) >> 4) + (input & 1);
        int column = (input & 30) >> 1;
        byte retval;

        switch (sboxIndex)
        {
            case 1:
                retval = S1[row][column];
                break;
            case 2:
                retval = S2[row][column];
                break;
            case 3:
                retval = S3[row][column];
                break;
            case 4:
                retval = S4[row][column];
                break;
            case 5:
                retval = S5[row][column];
                break;
            case 6:
                retval = S6[row][column];
                break;
            case 7:
                retval = S7[row][column];
                break;
            case 8:
                retval = S8[row][column];
                break;
            default:
                retval = -1;
                break;
        };

        return retval;
    }

    /**
     * Returns an ArrayList containing the possible input values to the
     * specified SBox would produce the specified output.
     *
     * @param value int value specifying the output of an SBox
     * @param sboxIndex int value specifying and index from 1-8
     *   indicating which SBox produced the output.
     */
    public ArrayList getInverseSBoxValues(int value, int sboxIndex)
    {
        ArrayList retVals = new ArrayList<Integer>(4);

        switch (sboxIndex)
        {
            case 1:
                for (int i=0; i<16; i++)
                {
                    if (S1[0][i] == value)
                    {
                        retVals.add(new Integer(i<<1));
                    }
                    if (S1[1][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x01));
                    }
                    if (S1[2][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x20));
                    }
                    if (S1[3][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x21));
                    }
                }
                break;
            case 2:
                for (int i=0; i<16; i++)
                {
                    if (S2[0][i] == value)
                    {
                        retVals.add(new Integer(i<<1));
                    }
                    if (S2[1][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x01));
                    }
                    if (S2[2][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x20));
                    }
                    if (S2[3][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x21));
                    }
                }
                break;
            case 3:
                for (int i=0; i<16; i++)
                {
                    if (S3[0][i] == value)
                    {
                        retVals.add(new Integer(i<<1));
                    }
                    if (S3[1][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x01));
                    }
                    if (S3[2][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x20));
                    }
                    if (S3[3][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x21));
                    }
                }
                break;
            case 4:
                for (int i=0; i<16; i++)
                {
                    if (S4[0][i] == value)
                    {
                        retVals.add(new Integer(i<<1));
                    }
                    if (S4[1][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x01));
                    }
                    if (S4[2][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x20));
                    }
                    if (S4[3][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x21));
                    }
                }
                break;
            case 5:
                for (int i=0; i<16; i++)
                {
                    if (S5[0][i] == value)
                    {
                        retVals.add(new Integer(i<<1));
                    }
                    if (S5[1][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x01));
                    }
                    if (S5[2][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x20));
                    }
                    if (S5[3][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x21));
                    }
                }
                break;
            case 6:
                for (int i=0; i<16; i++)
                {
                    if (S6[0][i] == value)
                    {
                        retVals.add(new Integer(i<<1));
                    }
                    if (S6[1][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x01));
                    }
                    if (S6[2][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x20));
                    }
                    if (S6[3][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x21));
                    }
                }
                break;
            case 7:
                for (int i=0; i<16; i++)
                {
                    if (S7[0][i] == value)
                    {
                        retVals.add(new Integer(i<<1));
                    }
                    if (S7[1][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x01));
                    }
                    if (S7[2][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x20));
                    }
                    if (S7[3][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x21));
                    }
                }
                break;
            case 8:
                for (int i=0; i<16; i++)
                {
                    if (S8[0][i] == value)
                    {
                        retVals.add(new Integer(i<<1));
                    }
                    if (S8[1][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x01));
                    }
                    if (S8[2][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x20));
                    }
                    if (S8[3][i] == value)
                    {
                        retVals.add(new Integer((i<<1) & 0x21));
                    }
                }
                break;
            default:
                break;
        };

        return retVals;
    }

}
