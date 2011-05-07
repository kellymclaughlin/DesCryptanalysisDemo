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
 * Tuple.java
 *
 * Created on March 16, 2006, 11:55 AM
 *
 */

/**
 * This class represents a set of plaintext/ciphertext pairs where the xor of
 * the plaintext pairs is equal to the value of the characteristic.
 *
 * @author Kelly McLaughlin
 */
public class Tuple extends Object {

    private long x1;
    private long x2;
    private long y1;
    private long y2;
    private boolean valid;

    /** Creates a new instance of Tuple */
    public Tuple() {
        valid = true;
    }

    /**
     * Creates a new instance of Tuple
     *
     * @param x1 long value specifying the first plaintext value
     * @param x2 long value specifying the second plaintext value
     * @param y1 long value specifying the ciphertext value of x1
     * @param y2 long value specifying the ciphertext value of x2
     */
    public Tuple(long x1, long x2, long y1, long y2)
    {
        this.x1 = x1;
        this.x2 = x2;
        this.y1 = y1;
        this.y2 = y2;
        valid = true;
    }

    /**
     * Setter for the x1 member
     *
     * @param x1 long value specifying the first plaintext value
     */
    public void setX1(long x1)
    {
        this.x1 = x1;
    }

    /**
     * Getter for x1
     */
    public long getX1()
    {
        return x1;
    }

    /**
     * Setter for the x2 member
     *
     * @param x2 long value specifying the second plaintext value
     */
    public void setX2(long x2)
    {
        this.x2 = x2;
    }

    /**
     * Getter for x2
     */
    public long getX2()
    {
        return x2;
    }

    /**
     * Setter for the y1 member
     *
     * @param y1 long value specifying the ciphertext value of x1
     */
    public void setY1(long y1)
    {
        this.y1 = y1;
    }

    /**
     * Getter for y1
     */
    public long getY1()
    {
        return y1;
    }

    /**
     * Setter for the y2 member
     *
     * @param y2 long value specifying the ciphertext value of x2
     */
    public void setY2(long y2)
    {
        this.y2 = y2;
    }

    /**
     * Getter for y2
     */
    public long getY2()
    {
        return y2;
    }

    /**
     * Returns indication if this Tuple represents a valid
     * pair of input plaintexts.
     */
    public boolean isValid()
    {
        return valid;
    }

    /**
     * Marks this Tuple as invalid for use in the cryptanalysis
     * process.
     */
    public void invalidateTuple()
    {
        valid = false;
    }
}
