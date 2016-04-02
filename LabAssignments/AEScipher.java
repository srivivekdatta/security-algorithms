
/**
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 *
 * @author : Sri Vivek datta Immadisetty
 */
public class AEScipher {

  private static final String[][] S_BOX = {
    {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
    {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
    {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
    {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
    {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
    {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
    {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
    {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
    {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
    {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
    {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
    {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
    {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
    {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
    {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
    {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}};

  private static final String[][] R_CON = {
    {"8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A"},
    {"2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39"},
    {"72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A"},
    {"74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8"},
    {"AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF"},
    {"C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC"},
    {"83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B"},
    {"36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3"},
    {"7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94"},
    {"33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20"},
    {"40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35"},
    {"6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F"},
    {"25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04"},
    {"08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63"},
    {"C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD"},
    {"61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D"}};

  /**
   * Implementing Galois multiplication, Rijndael implementations simply uses
   * pre-calculated lookup tables to perform the byte multiplication by 2
   */
  public static int[][] Multiplicationby2Matrix = {
    {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16,
      0x18, 0x1a, 0x1c, 0x1e},
    {0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36,
      0x38, 0x3a, 0x3c, 0x3e},
    {0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56,
      0x58, 0x5a, 0x5c, 0x5e},
    {0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76,
      0x78, 0x7a, 0x7c, 0x7e},
    {0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96,
      0x98, 0x9a, 0x9c, 0x9e},
    {0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6,
      0xb8, 0xba, 0xbc, 0xbe},
    {0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6,
      0xd8, 0xda, 0xdc, 0xde},
    {0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6,
      0xf8, 0xfa, 0xfc, 0xfe},
    {0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d,
      0x03, 0x01, 0x07, 0x05},
    {0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d,
      0x23, 0x21, 0x27, 0x25},
    {0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d,
      0x43, 0x41, 0x47, 0x45},
    {0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d,
      0x63, 0x61, 0x67, 0x65},
    {0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d,
      0x83, 0x81, 0x87, 0x85},
    {0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad,
      0xa3, 0xa1, 0xa7, 0xa5},
    {0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd,
      0xc3, 0xc1, 0xc7, 0xc5},
    {0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed,
      0xe3, 0xe1, 0xe7, 0xe5}};
  /*
   * rather than implementing galois multiplication, Rijndael implementations
   * simply uses pre-calculated lookup tables to perform the byte multiplication
   * by 3
   */
  public static int[][] Multiplicationby3Matrix = {
    {0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d,
      0x14, 0x17, 0x12, 0x11},
    {0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d,
      0x24, 0x27, 0x22, 0x21},
    {0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d,
      0x74, 0x77, 0x72, 0x71},
    {0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d,
      0x44, 0x47, 0x42, 0x41},
    {0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd,
      0xd4, 0xd7, 0xd2, 0xd1},
    {0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed,
      0xe4, 0xe7, 0xe2, 0xe1},
    {0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd,
      0xb4, 0xb7, 0xb2, 0xb1},
    {0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d,
      0x84, 0x87, 0x82, 0x81},
    {0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86,
      0x8f, 0x8c, 0x89, 0x8a},
    {0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6,
      0xbf, 0xbc, 0xb9, 0xba},
    {0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6,
      0xef, 0xec, 0xe9, 0xea},
    {0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6,
      0xdf, 0xdc, 0xd9, 0xda},
    {0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46,
      0x4f, 0x4c, 0x49, 0x4a},
    {0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76,
      0x7f, 0x7c, 0x79, 0x7a},
    {0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26,
      0x2f, 0x2c, 0x29, 0x2a},
    {0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16,
      0x1f, 0x1c, 0x19, 0x1a}};

  private static final String[][] mainKey = new String[4][4];
  public static String[][] matrixW = new String[4][44];

  public static String[][] roundKeys(String input) {

    createFirstKey(input);

    for (int row = 0; row <= 3; row++) {
      for (int column = 0; column <= 3; column++) {
        matrixW[row][column] = mainKey[row][column];
      }
    }

    String[][] new_w = null;
    for (int column = 4; column <= 43; column++) {

      if (column % 4 != 0) {
        for (int row = 0; row <= 3; row++) {
          matrixW[row][column] = doXOR(matrixW[row][column - 4], matrixW[row][column - 1]);
        }
      } else {

        // if the column is a divisor of 4 then use new_w to store the previous values
        new_w = new String[1][4];

        new_w[0][0] = matrixW[1][column - 1];
        new_w[0][1] = matrixW[2][column - 1];
        new_w[0][2] = matrixW[3][column - 1];
        new_w[0][3] = matrixW[0][column - 1];

        // transforming the matrix using the S-box
        for (int m = 0; m < 1; m++) {
          for (int n = 0; n <= 3; n++) {
            new_w[m][n] = Sbox(new_w[m][n]);
          }
        }

        int numRound = column / 4;
        new_w[0][0] = doXOR(R_CON[0][numRound], new_w[0][0]);

        for (int row = 0; row <= 3; row++) {
          matrixW[row][column] = doXOR(matrixW[row][column - 4], new_w[0][row]);
        }
      }
    }
    return matrixW;
  }

  /**
   * this matrix reads all the values into the Sbox
   *
   * @param in
   * @return output
   */
  public static String Sbox(String in) {
    int x = Integer.parseInt(in.split("")[0], 16);
    int y = Integer.parseInt(in.split("")[1], 16);
    String output = S_BOX[x][y];
    return output;
  }

  /**
   * doXOR this part does the XOR of val1 and val2
   *
   * @param a first input value
   * @param b second input value
   * @return result
   */
  public static String doXOR(String a, String b) {
    int val1 = Integer.parseInt(a, 16);
    int val2 = Integer.parseInt(b, 16);
    int XORval = val1 ^ val2;
    String res = Integer.toHexString(XORval);
    if (res.length() == 1) {
      res = "0" + res;
    }
    return res;
  }

  /**
   * values are stored in 4*4 matrix using input
   *
   * @param input
   */
  public static void createFirstKey(String input) {

    int i = 0, row;
    for (int column = 0; column <= 3; column++) {
      for (row = 0; row <= 3; row = row + 1) {
        mainKey[row][column] = input.substring(i, i + 2);
        i = i + 2;
      }
    }
  }

  public void rounds(String key, String text) {
    int i = 0;
    String[][] output = new String[4][4];
    String[][] roundKey = new String[4][4];
    for (int column = 0; column <= 3; column++) {
      for (int row = 0; row <= 3; row = row + 1) {
        output[row][column] = text.substring(i, i + 2);
        i = i + 2;
      }
    }

    roundKeys(key);
    int a = 0;
    int b = 0;

    while (a < 44) {
      for (int j = 0; j < 4; j++, a++) {
        for (int k = 0; k < 4; k++) {
          roundKey[k][j] = matrixW[k][a];
        }
      }

      if (b != 10) {
        b++;
        output = aesStateXOR(roundKey, output);

        output = aesNibblesub(output);

        output = aesShiftRow(output);

        if (b != 10) {
          output = aesMixColumn(output);
        }
      } else {
        output = aesStateXOR(output, roundKey);
      }

    }
    for (int cols = 0; cols < 4; cols++) {
      for (int row = 0; row < 4; row++) {
        System.out.print(output[row][cols]);
      }
    }

  }

  /**
   * create the keyHex and sHex matrices which are to be XORed
   *
   * @param keyHex
   * @param sHex
   * @return
   */
  public static String[][] aesStateXOR(String[][] keyHex, String[][] sHex) {

    String[][] new_matrix = new String[4][4];
    int col = 0;

    for (int k = 0; k <= 3; k++, col++) {
      for (int row = 0; row <= 3; row++) {
        new_matrix[k][row] = doXOR(sHex[k][row], keyHex[k][row]);
      }
    }
    return new_matrix;
  }

  /**
   * this method will perform the Substitution operation, i.e., the entries of
   * the output matrix result from running the corresponding input matrix
   * entries through the AES S-Box.
   */
  public static String[][] aesNibblesub(String[][] inStateHex) {
    String sOut;
    String[][] outStateHex = new String[4][4];

    for (int row = 0; row <= 3; row++) {
      for (int k = 0; k <= 3; k++) {
        outStateHex[k][row] = Sbox(inStateHex[k][row]);
      }
    }
    return outStateHex;
  }

  /**
   * aesShiftRow will perform the Shift Row operation of the AES to transform
   * the input state matrix into output state
   *
   * @param arr array that has the values
   * @param cnt the place of the value in the array
   * @return array
   */
  private String[][] aesShiftRow(String[][] inStateHex) {
    String[][] outStateHex = new String[4][4];
    int cnt = 0;
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        outStateHex[i][j] = inStateHex[i][(j + cnt) % 4];
      }
      cnt++;
    }
    return outStateHex;
  }

  /**
   * aesMixColumn uses mixColMat's inputs and gives the result matrix.
   *
   */
  public static int[][] mixColumnMatrix = {{0x02, 0x03, 0x01, 0x01},
  {0x01, 0x02, 0x03, 0x01}, {0x01, 0x01, 0x02, 0x03},
  {0x03, 0x01, 0x01, 0x02}};

  /**
   * The aesMixColumn function takes input as four bytes and outputs four bytes,
   * where each input byte affects all four output bytes.
   *
   *
   * @param k it is the key
   * @return null
   */
  public static String[][] aesMixColumn(String[][] k) {
    try {
      String aesMixColumnMatrix[][] = new String[4][4];
      for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
          aesMixColumnMatrix[i][j] = mixColAdd(k, mixColumnMatrix, i,
            j);
        }
      }
      return aesMixColumnMatrix;
    } catch (Exception mixcolumn) {
      return null;
    }
  }

  /**
   * mixColumnAddition
   *
   * In Rijndael's Galois field, the addition is actually an XOR operation, and
   * then multiplication.
   *
   *
   * @param Key
   * @param mixcolumn
   * @param i
   * @param j
   * @return
   */
  public static String mixColAdd(String[][] Key, int[][] mixcolumn, int i,
    int j) {
    int sum = 0;
    for (int k = 0; k < 4; k++) {
      int a = mixcolumn[i][k];
      int b = Integer.parseInt(Key[k][j], 16);
      sum = sum ^ mixColumnMultiplication(a, b);
    }
    String result = String.format("%02x", sum);
    return result.toUpperCase();
  }

  /*
   * mixColumnMultiplication
   * 
   * final result is passed to the mixColumnAddition method and then OXR
   * to get the sum.
   * 
   * MixColumns step can be performed by multiplying four
   * numbers in Rijndael's Galois field.
   */
  public static int mixColumnMultiplication(int a, int b) {
    if (a == 1) {
      return b;
    } else if (a == 2) {
      return Multiplicationby2Matrix[b / 16][b % 16];
    } else if (a == 3) {
      return Multiplicationby3Matrix[b / 16][b % 16];
    }
    return 0;
  }
}
