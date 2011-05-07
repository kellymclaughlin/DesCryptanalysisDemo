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
 * DesCryptAnalysisApplet.java
 *
 * Created on April 15, 2006, 9:47 AM
 *
 */

import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpringLayout;
import javax.swing.text.BadLocationException;

/**
 * This class implements a JApplet that presents a user with an input text area
 * for input ciphertext/plaintex pairs in the form of line separated entries of the
 * form { plaintext1;plaintext2;ciphertext1;ciphertext2 }. The first set of entires
 * should correspond to input pairs for the first characteristic (i.e. plaintext1
 * xor plaintext2 == 0x4008000004000000). The second set of entries should correspond
 * to the input pairs for the second characteristic (i.e. plaintext1 xor plaintext2
 * == 0x0020000800000400). The two sets of entries should be separated by a line
 * containing only 20 dashes (i.e. --------------------).
 *
 * @author Kelly McLaughlin
 */
public class DesCryptanalysisApplet extends javax.swing.JApplet {
    private final int VERTICAL_SPACING_CONSTANT = 35;
    private SpringLayout layout;
    private JLabel appletTitleLabel;
    private JLabel ciphertextLabel;
    private JLabel plaintextLabel;
    private JLabel keyLabel;
    private JLabel detailsLabel;

    private JTextField ciphertextTextField;
    private JTextField plaintextTextField;
    private JTextArea pairsTextArea;
    private JTextArea detailsTextArea;
    private JScrollPane pairsScrollPane;
    private JScrollPane detailsScrollPane;
    private JTextField keyTextField;
    private JButton computeKeyButton;
    private JPanel errorPane;
    private GridBagConstraints c;

    /** Creates a new instance of DesCryptAnalysisApplet */
    public DesCryptanalysisApplet() {
    }

    /**
     * This method is called by a browser to initialize an applet before the start() method is called.
     */
    public void init()
    {
        Container cp = getContentPane();

        appletTitleLabel = new JLabel("DES Cryptanalysis Demonstration Applet");
        ciphertextLabel = new JLabel("Plaintext/Ciphertext Pairs:");
        plaintextLabel = new JLabel("Plaintext:");
        keyLabel = new JLabel("Key:");
        detailsLabel = new JLabel("Details:");

        ciphertextTextField = new JTextField(30);
        plaintextTextField = new JTextField(30);
        pairsTextArea = new JTextArea(24, 30);
        detailsTextArea = new JTextArea(10, 30);
        pairsScrollPane = new JScrollPane(pairsTextArea);
        detailsScrollPane = new JScrollPane(detailsTextArea);
        keyTextField = new JTextField(30);

        computeKeyButton = new JButton("Compute Key");

        layout = new SpringLayout();
        cp.setLayout(layout);

        //Add the title to the content pane
        layout.putConstraint(SpringLayout.WEST, appletTitleLabel, 75, SpringLayout.WEST, cp);
        cp.add(appletTitleLabel);

        layout.putConstraint(SpringLayout.WEST, ciphertextLabel, 5, SpringLayout.WEST, cp);
        layout.putConstraint(SpringLayout.NORTH, ciphertextLabel, VERTICAL_SPACING_CONSTANT, SpringLayout.NORTH, cp);
        cp.add(ciphertextLabel);

        layout.putConstraint(SpringLayout.WEST, pairsScrollPane, 30, SpringLayout.WEST, cp);
        layout.putConstraint(SpringLayout.NORTH, pairsScrollPane, VERTICAL_SPACING_CONSTANT+20, SpringLayout.NORTH, cp);
        cp.add(pairsScrollPane);

        layout.putConstraint(SpringLayout.WEST, computeKeyButton, 140, SpringLayout.WEST, cp);
        layout.putConstraint(SpringLayout.NORTH, computeKeyButton, VERTICAL_SPACING_CONSTANT+430, SpringLayout.NORTH, cp);
        cp.add(computeKeyButton);

        layout.putConstraint(SpringLayout.WEST, keyLabel, 5, SpringLayout.WEST, cp);
        layout.putConstraint(SpringLayout.NORTH, keyLabel, VERTICAL_SPACING_CONSTANT+460, SpringLayout.NORTH, cp);
        cp.add(keyLabel);

        layout.putConstraint(SpringLayout.WEST, keyTextField, 30, SpringLayout.WEST, cp);
        layout.putConstraint(SpringLayout.NORTH, keyTextField, VERTICAL_SPACING_CONSTANT+480, SpringLayout.NORTH, cp);
        cp.add(keyTextField);

        layout.putConstraint(SpringLayout.WEST, detailsLabel, 5, SpringLayout.WEST, cp);
        layout.putConstraint(SpringLayout.NORTH, detailsLabel, VERTICAL_SPACING_CONSTANT+530, SpringLayout.NORTH, cp);
        cp.add(detailsLabel);

        layout.putConstraint(SpringLayout.WEST, detailsScrollPane, 30, SpringLayout.WEST, cp);
        layout.putConstraint(SpringLayout.NORTH, detailsScrollPane, VERTICAL_SPACING_CONSTANT+550, SpringLayout.NORTH, cp);
        cp.add(detailsScrollPane);

        //Add the action listener for the compute button
        computeKeyButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                ArrayList pairsInput = new ArrayList<String>();
                detailsTextArea.setText("");

                //Get the input from the UI fields
                int lineCount = pairsTextArea.getLineCount();

                if (lineCount == 0)
                {
                    keyTextField.setText("Error: Must enter plaintext/ciphertext pairs.");
                    return;
                }

                for (int i=0; i<lineCount; i++)
                {
                    try
                    {
                        int beginLineOffset = pairsTextArea.getLineStartOffset(i);
                        int endLineOffset = pairsTextArea.getLineEndOffset(i);
                        pairsInput.add(pairsTextArea.getText(beginLineOffset, endLineOffset-beginLineOffset));
                    }
                    catch (BadLocationException ex)
                    {
                        return;
                    }
                }

                DesCryptanalysis dca = new DesCryptanalysis();
                long key = dca.determineKey(pairsInput);

                if (key == 0)
                {
                    keyTextField.setText("Error: Could not determine key.");
                    return;
                }
                else
                {
                    keyTextField.setText(Long.toString(key));
                }

                //Add information to details text box
                detailsTextArea.append("Number of input pairs for Characteristic One: " + Integer.toString(dca.getNumberOfCharOneTuples()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("Number of input pairs for Characteristic Two: " + Integer.toString(dca.getNumberOfCharTwoTuples()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("Characteristic One Information:");
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 2 Key Bits: " + Integer.toString(dca.getCharOneS2KeyBits()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 5 Key Bits: " + Integer.toString(dca.getCharOneS5KeyBits()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 6 Key Bits: " + Integer.toString(dca.getCharOneS6KeyBits()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 7 Key Bits: " + Integer.toString(dca.getCharOneS7KeyBits()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 8 Key Bits: " + Integer.toString(dca.getCharOneS8KeyBits()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("Characteristic Two Information:");
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 1 Key Bits: " + Integer.toString(dca.getCharTwoS1KeyBits()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 2 Key Bits: " + Integer.toString(dca.getCharTwoS2KeyBits()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 4 Key Bits: " + Integer.toString(dca.getCharTwoS4KeyBits()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 5 Key Bits: " + Integer.toString(dca.getCharTwoS5KeyBits()));
                detailsTextArea.append("\r\n");
                detailsTextArea.append("    SBox 6 Key Bits: " + Integer.toString(dca.getCharTwoS6KeyBits()));
                detailsTextArea.append("\r\n");
            }
        });
    }

}
