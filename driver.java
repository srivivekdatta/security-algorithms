/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.util.Scanner;

/**
 *
 * @author Admin
 */
public class driver {

  public static void main(String args[]) {

    Scanner sc = new Scanner(System.in);
    String input = sc.nextLine();

    AES_cipher as = new AES_cipher();
    as.roundKeys(input);
  }
}
