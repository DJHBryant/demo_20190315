package com.ghbank.openapi.util;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//import org.apache.commons.lang.StringEscapeUtils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * RSA工具类
 * @author even
 * 提供了RSA签名和验签方法
 * 1、签名
 * 0）.请将报文使用md5提取报文摘要。
 * 2）.再将摘要用已方私钥进行签名。
 * 2、验签
 * 1）.请将报文使用md5提取报文摘要。
 * 2）.再将摘要使用对方公钥进行签名。
 * 
 * 
 */
public class RSAUtil {
    public static final String KEY_ALGORITHM = "RSA";
    
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String PUBLIC_KEY = "publicKey";
    public static final String PRIVATE_KEY = "privateKey";
    
    
    //测试私钥
    public static String privateString="MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCT10hm21I5vpyibwvqxXjt6zKBI45DFzT+ana7er09Mj5rTuOxivmZ7FAsUv1+YT8swWVweZkMz3khDyMXDWPSC7xHX58LjKxazOJvd/pTCvb8+a1dRIYhQnZGRV7wNIhSzJ32htK4rJXfpGXqrl+mZBO5RLD3IB8vagysBxjVGF3ZUfafw3mpGZFux3AwqQJtfZFxC3VzeRPGeleAnpdrA5qeYXcbzey7+bRNXGsNd2I5Wj1APvFA0QJHzytr9/6CEPE7FSM3Z2FnLTTgv8OAy63CuhyZZreOyZAYusT5NxpVKOpd9EBkLBCQRgmxOPVcjzI3ZbRlnSudtzZZOowTAgMBAAECggEARVsUmzQ+wdo7LzS7OXtEfRD+k3izr6O+d7BIXTF6f7AHel37EXpqGBy1i+WvCE/kzEE6LmbNNyZJ5Alu48yjTJG21SD1wvxOixZdEAAQDk8xiYI0I3IXHplIVTUMEdIDNhzJ6jJbvskwUkeUjGEbfDqsyhiAkJ6gIqU0pqt5qdXahJKvxt9F1nJck9LoMMQ+nuOoC9wgfQYEOk3ejOdYcqmoC9VVn+LOz1fhjTfr+o6tanH/E0oncvzf3sAUDUJm+EEBnppzIJmUWByghulcqK578El8Tm+ffieHnzy8n6SyZKKh3QZw1i8MaYAIQOwwjY0NRfjsy21TWM6Wo3nbYQKBgQDRP5lA+hM3o7cDwrrnnkw4aT6RgLzr/smBdt11TMwTZoIAjYbrXugOSHOneKkXB85tcE2YCo/T0d9jhS1yMIofptnTIivwzEl5g6/w+hCXXLOohdbFBcRtQ86hleHdezuAg2L/AekNJkFiu2o3I+C49ojruZeNHXjGluRDPoWlMQKBgQC031rVQi1qsteXXvdK1UEgBT4zcUZ/uIbCz33EunJsnrJSq3unEFWyeBj02Xv8/00l1gkPgzGtdOcnpMgNZwo3ZTyMK1hon7fW3yjlLpoGy8f6/WC8L+hIqalKqb732+U4AS0OaKwv3Um4wnpv5kKiBJtp7dZj7fTLKLr1BNZEgwKBgF3K5Cb78SE/gQluf9jSW9ftVN5jlksyKaCeZyXtBoyrphoZViCqqdm9IBoxO5nXJfBoJl/AXDfWGwvA5l4I4+DMKVc6Off1mfmdzX92l3lBVEZ1t48YxrMzcat8Q4HDeyhfvEAR2yTJwQVAfJu6uUAvQbBnwEbAryJVAHwjykQBAoGBAIdQFX83rAyH0TwgQrcMRVV0Nq17j/dbEA5L9lYn+hSCwPuR6Mb6NHJ44IrE7bo/MPMeZdbiGlce/xOsdjF4pa79oMdoYhKbcohgmRKjw31UFL8Tsbv3xzodG1aNGR4KtzgnwRJngnGohk+fxsNSKwVUlwQvd1V5HsqiJQPK45WLAoGBAM3D5tUPVFqSIAxh3ri5XpXgWq4nQcMD03K6Q/PKP++gQGDNj6mgYwkoO9pvdfJBUY3B/sUDJyvnkjRGgS90V1iUlF/1h5XtK2Z8MHrgUZHZVvR3U1oBy0zY8r+VfjihjYGkMZkZBge0fBsxPln8dM3mm3IgCrPyJEsgK0keF1bX";
    //测试公钥
    public static String publicStr="MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDRs7+q/7N3ElgxuXpUXFmP7b+3H36I6SJ+Tl9mMktSTn5ykdGiZV89FNCqbZqBzi8q1F6WC3DHkqXEL4yNiQsRYubFmn0U0YRltnqsmzUOIR2nGLuYprg5ApuQ+dIH725YnZ453HNyvEZZbGxyVgjWh05+wkSV6HmfiB6fcTBfkwIBAw==";
 			
    
    /** RSA密钥长度必须是64的倍数，在512~65536之间。默认是1024 */
    public static final int KEY_SIZE = 2048;

    //签名原文(加密之后(body)+requestId+requestTime)
    public static final String PLAIN_TEXT = "ZVlWZUYxM1huaEhpRWErWVlMYVZDdz092019030515020517610000020190305150205176";  //原文
   
    
    public static void main(String[] args) throws Exception {

        // 生成秘钥对
//      Map<String, byte[]> keyMap = new HashMap<String, byte[]>();
//      keyMap = generateKeyBytes();
//      System.out.println(keyMap);
//      String publicKey = encryptBASE64(keyMap.get("publicKey"));
//      String privateKey = encryptBASE64(keyMap.get("privateKey"));
//      System.out.println("publicKey : " + publicKey);
//      System.out.println("privateKey : " + privateKey);
    	
    	
        //对原报文进行MD5提取摘要：
        String md5Result = MD5(PLAIN_TEXT);
        System.out.println("MD5摘要:\n" + md5Result);//转为大写
        
        //私钥签名流程
        PrivateKey privateKey = restorePrivateKey(decryptBASE64(privateString));
        byte[] encodedText = RSAEncode(privateKey, md5Result.getBytes("UTF-8"));
        
        //私钥签名后的数据 
        String privateResult = byteArrayToHexString(encodedText);//报文头前面256位的私钥签名后的结果privateResult
        System.out.println("签名后的256位数据:\n" + privateResult);
        System.out.println("压缩base64后（签名结果）:\n" + encryptBASE64(privateResult.getBytes("UTF-8")));
 
        // 公钥解密流程
        PublicKey publicKey = restorePublicKey(decryptBASE64(publicStr));
        System.out.println("公钥解密: "+ RSADecode(publicKey, hexStringToByte(privateResult)));
        
        //验签的话，解密后的内容与返回的<?xml>后的报文用MD5摘要比对如果一致则未被篡改
        
        //System.out.println(StringEscapeUtils.unescapeXml("&#25903;&#20184;&#35746;&#21333;&#39044;&#25480;&#26435;&#25104;&#21151;"));
    }

    /**
     * 生成密钥对。注意这里是生成密钥对KeyPair，再由密钥对获取公私钥
     * 
     * @return
     */
    public static Map<String, byte[]> generateKeyBytes() {

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            Map<String, byte[]> keyMap = new HashMap<String, byte[]>();
            keyMap.put(PUBLIC_KEY, publicKey.getEncoded());
            keyMap.put(PRIVATE_KEY, privateKey.getEncoded());
            return keyMap;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥，X509EncodedKeySpec 用于构建公钥的规范
     * 
     * @param keyBytes
     * @return
     */
    public static PublicKey restorePublicKey(byte[] keyBytes) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);

        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
    }

    /**
     * 私钥，PKCS8EncodedKeySpec 用于构建私钥的规范
     * 
     * @param keyBytes
     * @return
     */
    public static PrivateKey restorePrivateKey(byte[] keyBytes) {
    	
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                keyBytes);
     
            KeyFactory factory;
			try {
				factory = KeyFactory.getInstance(KEY_ALGORITHM);
				  PrivateKey privateKey = factory
                  .generatePrivate(pkcs8EncodedKeySpec);
				  return privateKey;
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
          
 
        return null;
    }

    /**
     * 签名
     * 
     * @param key
     * @param plainText
     * @return
     */
    public static byte[] RSAEncode(PrivateKey key, byte[] plainText) {

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;

    }

    /**
     *验签
     * 
     * @param key
     * @param encodedText
     * @return
     */
    public static String RSADecode(PublicKey key, byte[] encodedText) {

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(encodedText));
        } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;

    }
    
    
    public static byte[] decryptBASE64(String key) throws Exception{
		return (new BASE64Decoder()).decodeBuffer(key);
	}
	
	public static String encryptBASE64(byte[] key) throws Exception{
		
		return (new BASE64Encoder()).encodeBuffer(key);
	} 
	
	// 将字节转换为十六进制字符串
	private static String byteToHexString(byte ib) {
		char[] Digit = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
				'B', 'C', 'D', 'E', 'F' };
		char[] ob = new char[2];
		ob[0] = Digit[(ib >>> 4) & 0X0F];
		ob[1] = Digit[ib & 0X0F];
		String s = new String(ob);
		return s;
	}

	// 将字节数组转换为十六进制字符串
	public static String byteArrayToHexString(byte[] bytearray) {
		String strDigest = "";
		for (int i = 0; i < bytearray.length; i++)
		{
			strDigest += byteToHexString(bytearray[i]);
		}
		return strDigest;
	}
	
	//MD5摘要
	public static String MD5(String srcData) throws NoSuchAlgorithmException{
		char hexDigits[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};       

            byte[] btInput = srcData.getBytes();
            // 获得MD5摘要算法的 MessageDigest 对象
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            // 使用指定的字节更新摘要
            mdInst.update(btInput);
            // 获得密文
            byte[] md = mdInst.digest();
            // 把密文转换成十六进制的字符串形式
            int j = md.length;
            char str[] = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str).toUpperCase();
   
	}
	
	//16进制字符串转为字节数组
	public static byte[] hexStringToByte(String hex){
		int len = (hex.length()/2);
		byte[] result = new byte[len];
		char[] achar=hex.toCharArray();
		for(int i=0;i<len;i++){
			int pos=i*2;
			result[i]=(byte)(toByte(achar[pos])<<4|toByte(achar[pos+1]));
		}
		return result;
	}
	
	public static int toByte(char c){
		byte b=(byte)"0123456789ABCDEF".indexOf(c);
		return b;
	}
	
    /*
        加密数据
     */
    public static String encodeData(PublicKey publicKey,String originData){
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] bytesEncrypt = cipher.doFinal(originData.getBytes());
            //Base64编码
            byte[] bytesEncryptBase64 = Base64.getEncoder().encode(bytesEncrypt);
            return new String(bytesEncryptBase64);            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }
    /*
        解密数据
     */
    public static String decodeData(PrivateKey privateKey,String encodeData){
        try {
            //Base64解码
            byte[] bytesEncrypt = Base64.getDecoder().decode(encodeData);
            //加密
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            byte[] bytesDecrypt = cipher.doFinal(bytesEncrypt);
//            byte[] bytesDecrypt = cipher.doFinal(encodeData.getBytes());
            return new String(bytesDecrypt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }   	
	
}