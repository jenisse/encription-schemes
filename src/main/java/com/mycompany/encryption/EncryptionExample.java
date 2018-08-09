/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.encryption;


/**
 *
 * @author TOSHIBA
 */
public class EncryptionExample {
    public static void main(String[] args){
        String DATA = "0123456789abcdef";
        String ENCRYPT_SCHEME = "DES"; //change it to DES for test DES scheme
        try{
           SecurityService securityService = new SecurityService(); 
           System.out.println("--------------------RSA Encryption and Decryption Test-----------------------------");
           securityService.RSAOnlyEncryptAndDecrypt(DATA);
           System.out.println("--------------------DES or AES Encryption and Decryption Test-----------------------------");
           securityService.DESorAESOnlyEncryptAndDecrypt(DATA, ENCRYPT_SCHEME);
           System.out.println("--------------------DES/RSA Encryption and Decryption Test-----------------------------");
           securityService.DESwithRSAEncryptAndDecrypt(DATA, ENCRYPT_SCHEME);
           System.out.println("--------------------SHA Encoding Test-----------------------------");
           securityService.ConvertwithSHA(DATA);
           System.out.println("--------------------HMAC Encoding Test-----------------------------");
           securityService.ConvertwithHMAC(DATA);
           
        } catch (Exception e){
            e.printStackTrace();
        }
    }
    
    
}
