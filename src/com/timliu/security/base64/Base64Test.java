package com.timliu.security.base64;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Base64Test 
{

	public static final String src = "base64 test";
	public static void main(String[] args) 
	{
		jdkBase64();
		
		commonsCodesBase64();

		bouncyCastleBase64();
	}
	
	// 用jdk实现
	public static void jdkBase64()
	{
		try 
		{
			BASE64Encoder encoder = new BASE64Encoder();
			String encode = encoder.encode(src.getBytes());
			System.out.println("encode:" + encode);
			
			BASE64Decoder decoder = new BASE64Decoder();
			System.out.println("decode:" + new String(decoder.decodeBuffer(encode)));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	// 用Apache的common codes实现
	public static void commonsCodesBase64()
	{
		byte[] encodeBytes = Base64.encodeBase64(src.getBytes());
		System.out.println("common codes encode:" + new String(encodeBytes));
		
		byte[] dencodeBytes = Base64.decodeBase64(encodeBytes);
		System.out.println("common codes decode:" + new String(dencodeBytes));
		
	}
	

	// 用bouncy castle实现
	public static void bouncyCastleBase64()
	{
		byte[] encodeBytes = org.bouncycastle.util.encoders.Base64.encode(src.getBytes());
		System.out.println("bouncy castle encode:" + new String(encodeBytes));
		
		byte[] dencodeBytes = org.bouncycastle.util.encoders.Base64.decode(encodeBytes);
		System.out.println("bouncy castle decode:" + new String(dencodeBytes));
		
	}

}
