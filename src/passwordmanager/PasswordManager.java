/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package passwordmanager;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.*;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.symmetric.AES.KeyGen;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
/**
 *
 * @author yunfjiang
 */
public class PasswordManager {

    /**
     * @param args the command line arguments
     */
	
	static SecretKey Key;
	int iv;
	static BlockCipher engine = new AESEngine();
	static byte[] test=new byte[32];
    
public static String get_SHA_512_SecurePassword(String passwordToHash, String   salt) throws UnsupportedEncodingException{
String generatedPassword = null;
    try {
         MessageDigest md = MessageDigest.getInstance("SHA-512");
         md.update(salt.getBytes("UTF-8"));
         byte[] bytes = md.digest(passwordToHash.getBytes("UTF-8"));
         StringBuilder sb = new StringBuilder();
         for(int i=0; i< bytes.length ;i++){
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
         }
         generatedPassword = sb.toString();
        } 
       catch (NoSuchAlgorithmException e){
        e.printStackTrace();
       }
    return generatedPassword;
}
	
	public static boolean check_integrity() throws IOException, NoSuchAlgorithmException, InvalidKeyException{
		RandomAccessFile accessor = new RandomAccessFile (new File("passwd_file"), "rws");
		
		if (accessor.length()==0){

			Mac mac = Mac.getInstance("HmacMD5");
			mac.init(Key);
			//System.out.println(Key.toString());


			//mac.update(, 0, Key.getEncoded().length);
			byte[] macbytes = mac.doFinal();
			//System.out.println(macbytes.length);
			accessor.write(macbytes);
			//System.out.println(macbytes);
			byte[] test=new byte[(int) accessor.length()];
			accessor.seek(0);
			accessor.read(test);
			
			//System.out.println(test);
			//if (Arrays.areEqual(macbytes, test))System.out.println("true");
			//else System.out.println("false");
			return true;
		}
		if ((int)(accessor.length())>16) {
			//calculate the MAC
			byte[] allpre=new byte [(int) accessor.length()-16];
			accessor.read(allpre);
			//System.out.println(allpre.toString());
			Mac mac = Mac.getInstance("HmacMD5");
			mac.init(Key);


			mac.update(allpre, 0, allpre.length);
			byte[] macbytes = mac.doFinal();
			
			byte[] macnow=new byte[16];
			accessor.read(macnow);
			if (Arrays.areEqual(macnow,macbytes)){
				System.out.println("PASSED!\n");
				accessor.close();
				return true;
			}
			else {
				
				System.out.println("FAILED!\n");
				accessor.close();
				return false;
			}
			
		}
		
		return true;
	}
	
	public static void register(String name, String password, String dn) throws Exception{
		File myFile = new File ("passwd_file");
		//Create the accessor with read-write access.
		RandomAccessFile accessor = new RandomAccessFile (myFile, "rws");
		byte[] allpre=new byte [(int) accessor.length()];
		//store all previous data into allpre
		
		accessor.read(allpre);
		accessor.seek(0);
	
        KeyParameter key = new KeyParameter(Arrays.copyOfRange(Key.getEncoded(),0,256 / Byte.SIZE));

		byte[] input=encryptWithAES_CTR(key,name);
		byte[] stand=new byte[32];
		for (int i=0;i<input.length;i++){
			stand[i]=input[i];
			
		}
		accessor.write(stand);
		//test=stand;
		stand=new byte[32];
		input=encryptWithAES_CTR(key,password);
		
		for (int i=0;i<input.length;i++){
			stand[i]=input[i];
			
		}
		accessor.write(stand);
		stand=new byte[32];
		input=encryptWithAES_CTR(key,dn);
		test=input;
		
		for (int i=0;i<input.length;i++){
			stand[i]=input[i];
			
		}
		accessor.write(stand);
		accessor.write(allpre);

		//file is updated with added account
		//calculate new mac

		accessor.seek(0);
		allpre=new byte[(int) accessor.length()-16];
		accessor.read(allpre);
		Mac mac = Mac.getInstance("HmacMD5");
	    mac.init(Key);
	
	    
	    mac.update(Arrays.copyOfRange(allpre,0,allpre.length), 0, allpre.length);
	    byte[] macbytes = mac.doFinal();
	    
	    //rewrite the MAC in file
	    accessor.seek(accessor.length()-16);
		accessor.write(macbytes);
		accessor.close();
		System.out.println("Successfully added this account!");
		
	}

	static int IV_SIZE=16;
    private static byte[] encryptWithAES_CTR(KeyParameter key, String in)
            throws IllegalArgumentException, UnsupportedEncodingException,
            DataLengthException {
        // iv should be unique for each encryption with the same key
        byte[] ivData = new byte[IV_SIZE];
        
        //SecureRandom rng = new (5);
       // rng.nextBytes(ivData);
        ParametersWithIV iv = new ParametersWithIV(key, ivData);

        SICBlockCipher aesCTR = new SICBlockCipher(new AESFastEngine());

        aesCTR.init(true, iv);
        byte[] plaintext = in.getBytes("UTF-8");
        byte[] ciphertext = new byte[ivData.length + plaintext.length];
        System.arraycopy(ivData, 0, ciphertext, 0, IV_SIZE);
        aesCTR.processBytes(plaintext, 0, plaintext.length, ciphertext, IV_SIZE);
        return ciphertext;
    }

    private static String decryptWithAES_CTR(KeyParameter key, byte[] ciphertext)
            throws IllegalArgumentException, UnsupportedEncodingException,
            DataLengthException {
        if (ciphertext.length < IV_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short to contain IV");
        }

        ParametersWithIV iv = new ParametersWithIV(key, ciphertext, 0, IV_SIZE);

        SICBlockCipher aesCTR = new SICBlockCipher(new AESFastEngine());
        aesCTR.init(true, iv);
        byte[] plaintext = new byte[ciphertext.length - IV_SIZE];
        aesCTR.processBytes(ciphertext, IV_SIZE, plaintext.length, plaintext, 0);
        return new String(plaintext, "UTF-8");
    }
    
    public static void delete(String name, String pass,String dn) throws Exception{
    	File myFile = new File ("passwd_file");
		//Create the accessor with read-write access.
		RandomAccessFile accessor = new RandomAccessFile (myFile, "rws");
		//System.out.println(accessor.length());
		byte[] allpre=new byte [(int) accessor.length()-16];
		//store all previous data into allpre
		int counter=0;
		byte[] now=new byte[32];
		//standralize the current byte to check if it matches with the input username
		byte[] stand1=new byte[32];
		byte[] stand2=new byte[32];
		byte[] stand3=new byte[32];
		KeyParameter key = new KeyParameter(Arrays.copyOfRange(Key.getEncoded(),0,256 / Byte.SIZE));
		//System.out.println(Arrays.);
		byte[] input1=encryptWithAES_CTR(key,name);
		byte[] input2=encryptWithAES_CTR(key,pass);
		byte[] input3=encryptWithAES_CTR(key,dn);
		for (int i=0;i<input1.length;i++){
			stand1[i]=input1[i];
		}
		for (int i=0;i<input2.length;i++){

			stand2[i]=input2[i];
			
		}
		for (int i=0;i<input3.length;i++){
			stand3[i]=input3[i];
		}
		int time =(int) ((accessor.length()-16)/96);
	
		//compare (accsessor.length-16)/96 times 
		int pointer;
		boolean cont=false;
		boolean contains=false;
		accessor.seek(0);
		byte[] passed=new byte[96];
		for (int j=0;j<time;j++){
			pointer=(int) accessor.getFilePointer();
			accessor.read(now);
			
			//if it is, skip this and next 95 bytes because it is deleted
			//System.out.println(Arrays.areEqual(test,stand1));
			//System.out.println(Arrays.areEqual(test,now));
			if (Arrays.areEqual(now,stand1)&!cont){
				accessor.read(now);
				if (Arrays.areEqual(now, stand2)){
					accessor.read(now);
					if (!Arrays.areEqual(now, stand3)){
						accessor.seek(pointer);
						cont=true;
						j=j-1;
					
					}
					else {
						contains=true;
						break;
					}
				}
					
					
				else {
						accessor.seek(pointer);
						j=j-1;
						cont=true;
					
				}
				
			}
			//If it isn't, update this and next 95 bytes to allpre 
			else{
				accessor.seek(accessor.getFilePointer()-32);
				accessor.read(passed);
				for (int i=counter;i<counter+96;i++){
					
					allpre[i]=passed[i-counter];
					
				}
				counter=counter+96;
				cont=false;
			}
			
		
		}
		if (contains){
			Mac mac = Mac.getInstance("HmacMD5");
		
		mac.init(Key);
		mac.update(allpre, 0, allpre.length);
		byte[] macbytes = mac.doFinal();
		accessor.setLength(allpre.length+16);
		
		accessor.seek(0);
		accessor.write(allpre);
		accessor.write(macbytes);
		}
		else {
			System.out.println("USER ACCOUNT DOES NOT EXIST!\n");
		}
		accessor.close();
		
    }
    
    public static void change(String name, String oldpass,String dn,String newpass ) throws DataLengthException, IllegalArgumentException, IOException, NoSuchAlgorithmException, InvalidKeyException{
    	File myFile = new File ("passwd_file");
		//Create the accessor with read-write access.
		RandomAccessFile accessor = new RandomAccessFile (myFile, "rws");
		byte[] name1=new byte[32];
		byte[] oldpass1=new byte[32];
		byte[] dn1=new byte[32];
		KeyParameter key = new KeyParameter(Arrays.copyOfRange(Key.getEncoded(),0,256 / Byte.SIZE));
		byte[] stand1=new byte[32];
		byte[] chf=encryptWithAES_CTR(key,name);
		for (int i=0;i<chf.length;i++){
			stand1[i]=chf[i];
		}
		byte[] stand2=new byte[32];
		byte[] stand3=new byte[32];
		chf=encryptWithAES_CTR(key,oldpass);
		for (int i=0;i<chf.length;i++){
			stand2[i]=chf[i];
		}
		chf=encryptWithAES_CTR(key,dn);
		for (int i=0;i<chf.length;i++){
			stand3[i]=chf[i];
		}
		byte[] newpass1=new byte[32];
		chf=encryptWithAES_CTR(key,newpass);
		for (int i=0;i<chf.length;i++){
			newpass1[i]=chf[i];
		}
		boolean iffound=false;
		int time =(int) ((accessor.length()-16)/96);
		for (int j=0;j<time;j++){
			accessor.read(name1);
			if (Arrays.areEqual(name1, stand1)){
				//System.out.println("found user");

				accessor.read(oldpass1);
				if(Arrays.areEqual(oldpass1, stand2)){
					//System.out.println("found pass");
					accessor.read(dn1);
					if(Arrays.areEqual(dn1, stand3)){
						//System.out.println("found dn");
						iffound=true;
						accessor.seek(accessor.getFilePointer()-64);
						accessor.write(newpass1);
						accessor.seek(accessor.getFilePointer()+32);
						break;
					}
					else{
						
					}
				}
				else accessor.read(dn1);
					
				}
			accessor.read(oldpass1);
			accessor.read(dn1);
			
			}
		if (iffound){
			accessor.seek(0);
			byte[] allpre=new byte[(int) accessor.length()-16];
			accessor.read(allpre);
			Mac mac = Mac.getInstance("HmacMD5");
		    mac.init(Key);
		
		    
		    mac.update(Arrays.copyOfRange(allpre,0,allpre.length), 0, allpre.length);
		    byte[] macbytes = mac.doFinal();
		    
		    //rewrite the MAC in file
		    accessor.seek(accessor.length()-16);
			accessor.write(macbytes);
			accessor.close();
		}
		else System.out.println("USER ACCOUNT DOES NOT EXIST!\n");
    }
    
    public static void getpass(String dn) throws Exception{
    	File myFile = new File ("passwd_file");
		//Create the accessor with read-write access.
		RandomAccessFile accessor = new RandomAccessFile (myFile, "rws");
		byte[] name=new byte[32];
		byte[] pass=new byte[32];
		byte[] dnmaybe=new byte[32];
		KeyParameter key = new KeyParameter(Arrays.copyOfRange(Key.getEncoded(),0,256 / Byte.SIZE));
		byte[] stand=new byte[32];
		byte[] input3=encryptWithAES_CTR(key,dn);
		//System.out.println(Arrays.areEqual(test, input3));
		for (int i=0;i<input3.length;i++){
			stand[i]=input3[i];
		}
		int time =(int) ((accessor.length()-16)/96);
		String name1;
		String pass1;
		accessor.seek(0);
		boolean found=false;
		
		for (int j=0;j<time;j++){
			accessor.read(name);
			
			accessor.read(pass);

			accessor.read(dnmaybe);
			if (Arrays.areEqual(stand, dnmaybe)){
				name1=decryptWithAES_CTR(key,name);
				pass1=decryptWithAES_CTR(key,pass);
				System.out.println("username "+name1+"password "+pass1);
				accessor.close();
				found=true;
				break;
			}
		}
		if (!found){
			System.out.println("USER ACCOUNT DOES NOT EXIST!\n");
		}
		
		
    }

    public static void main(String[] args) throws Exception {
    
        //looking for file "“passwd file” and “master passwd,”
   
        try {
            BufferedReader passwd= new BufferedReader(new FileReader("master_passwd"));
            System.out.print("Enter your Master password: ");
            Scanner scanner = new Scanner(System.in);
            String masterp = scanner.next();
           //
           
            String youentered= get_SHA_512_SecurePassword(masterp,"salt");
           
            if (youentered.equals(passwd.readLine())){
            	System.out.println("Correct!\n");
            	// decode the base64 encoded string
            	byte[] decodedKey = Base64.decode(youentered);
            	// rebuild key using SecretKeySpec
            	SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
            	Key=originalKey;
            	
            	//System.out.println("k="+Key.toString());
            	if (check_integrity()==false){
            		System.out.println("INTEGRITY CHECK OF PASSWORD FILE FAILED!\n");
            		
            	}
            	System.out.print("next order:");
            	passwd.close();
                scanner=new Scanner(System.in);
                String order=scanner.next();
                String username;
                String password;
                String newpassword;
                String dn;
                while (true){
                	if (order.equals("register_account")){
                		System.out.print("Input username:");
                		username=scanner.next();
                		System.out.print("Input password:");
                		password=scanner.next();
                		System.out.print("Input domain name:");
                		dn=scanner.next();
                		register(username,password,dn);
                		
                		
                	}
                	else if(order.equals("delete_account")){
                		System.out.print("Input username:");
                		username=scanner.next();
                		System.out.print("Input password:");
                		password=scanner.next();
                		System.out.print("Input domain name:");
                		dn=scanner.next();
                		delete(username,password,dn);
                		
                	}
                	else if (order.equals("check_integrity")){
                		check_integrity();
                		
                	}
                	else if (order.equals("End")) break;
                	else if (order.equals("get_password")){
                		System.out.print("Input domain name:");
                		dn=scanner.next();
                		getpass(dn);
                	}
                	else if (order.equals("change_account")){

                		System.out.print("Input username:");
                		username=scanner.next();
                		System.out.print("Input old password:");
                		password=scanner.next();
                		System.out.print("Input new password:");
                		newpassword=scanner.next();
                		System.out.print("Input domain name:");
                		dn=scanner.next();
                		change(username,password,dn,newpassword);
                	}
                	else {
                		System.out.println("Don't understand");
                		
                	}
                	System.out.print("next order:");
            		scanner=new Scanner(System.in);
            		order=scanner.next();
                }
            }
        	
            else {System.out.println("Wrong Password!");}
           
            
            
            
       
            
        } catch (FileNotFoundException ex) {
            //Logger.getLogger(PasswordManager.class.getName()).log(Level.SEVERE, null, ex);
            Scanner scanner = new Scanner(System.in);
            System.out.print("Create your Master password: ");
            String masterp = scanner.next();
            File mfile=new File("master_passwd");
            mfile.createNewFile();
            File pfile=new File("passwd_file");
            pfile.createNewFile();
            FileWriter fw = new FileWriter(mfile);
            BufferedWriter out = new BufferedWriter(fw);
            out.write(get_SHA_512_SecurePassword(masterp,"salt"));

            out.flush();
            out.close();
            
        }
        
      
        
    }
    
}