package com.ghbank.openapi.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;


public class AESUtil {
	/**
	 * 加密算法key
	 */
	private static final String KEY_ALGORITHM_AES = "AES";
	/**
	 * 默认的加密算法
	 */
	private static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
	/**
	 * 字符编码
	 */
	private static final String CHARSET = "utf-8";
	/**
	 * AES 秘钥长度 （128位）
	 */
	private static final int KEY_LENGTH = 128;

	/**
	 * AES 加密
	 *
	 * @param content
	 *            待加密内容
	 * @param password
	 *            加密密码
	 * @return 返回Base64转码后的加密数据
	 * @throws Exception
	 */
	public static String encrypt(String content, String password) throws Exception {
		// 创建密码器
		Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
		byte[] byteContent = content.getBytes(CHARSET);
		// 初始化为加密模式的密码器
		cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(password));
		// 加密
		byte[] result = cipher.doFinal(byteContent);
		// 通过Base64转码返回
		return Base64.encodeBase64String(result);
	}

	/**
	 * AES 解密
	 *
	 * @param content 
	 * @param password 
	 * @return 明文 
	 * @throws Exception 
	 * 
	 */
	public static String decrypt(String content, String password) throws Exception {
		// 实例化
		Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
		// 使用密钥初始化，设置为解密模式
		cipher.init(Cipher.DECRYPT_MODE, getSecretKey(password));
		// 执行操作
		byte[] result = cipher.doFinal(Base64.decodeBase64(content));
		return new String(result, CHARSET);
	}

	/**
	 * 生成加密秘钥
	 *
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static SecretKeySpec getSecretKey(final String password) throws NoSuchAlgorithmException {
		// 返回生成指定算法密钥生成器的 KeyGenerator 对象
		KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM_AES);
		// AES 密钥长度为
		kg.init(KEY_LENGTH, new SecureRandom(password.getBytes()));
		// 生成一个密钥
		SecretKey secretKey = kg.generateKey();
		// 转换为AES专用密钥
		return new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM_AES);
	}

	public static void main(String[] args) {
		// 明文
//		String content = "{" + 
//				"    \"body\": {" + 
//				"         \"reqId\": \"IDC001-10.1.90.103-open-9xYF+d1e/wFQX?&tyyy=098~!@#$%#^$&%*&^&)((*&_*()+[];':<>?gate-1541407346893yDHTIkc\"" + 
//				"     }," + 
//				"    \"header\": {" + 
//				"        \"appId\": \"app0001\"," + 
//				"        \"errorCode\": \"SYEC0001\"," + 
//				"        \"errorMsg\": \"send msg format error.\"" + 
//				"     }" + 
//				"}";
//		String content = "{\"randomStr\":\"mer07287643218969136314\",\"agentNo\":\"201703210000173\",\"sign\":\"53A337F980FF4556D47E50F192F77AFE\",\"signType\":\"MD5\",\"merchantInfo\":{\"remitD0\":\"2\",\"businessLicense\":\"320483000067847\",\"addressInfo\":{\"address\":\"华强北福田路58号\",\"province\":\"广东省\",\"city\":\"深圳市\",\"district\":\"福田区\"},\"remitT1\":\"0\",\"bankCardInfo\":{\"bankAccountName\":\"周瑾\",\"bankAccountAddress\":\"中国华兴银行莲花北支行\",\"bankAccountType\":\"1\",\"bankAccountLineNo\":\"102100000089\",\"bankAccountNo\":\"62122*******521428\"},\"servicePhone\":\"95188\",\"businessLicenseType\":\"NATIONAL_LEGAL\",\"fullName\":\"balabala巴辣香锅会展中心店\",\"shortName\":\"巴辣香锅\"},\"merchantNo\":\"201703210006450\"}";
		// 更换秘钥时加密明文为空
		String content = "";
		// 密文
		String secretContent = "";
		// 加密秘钥
//		String appSecret = "wggSlAgEAAoIBAQCrh1qYykpLwg/CtPt";
		// 更换秘钥时加密秘钥为行方公钥值
		String appSecret = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk9dIZttSOb6com8L6sV47esygSOOQxc0/mp2u3q9PTI+a07jsYr5mexQLFL9fmE/LMFlcHmZDM95IQ8jFw1j0gu8R1+fC4ysWszib3f6Uwr2/PmtXUSGIUJ2RkVe8DSIUsyd9obSuKyV36Rl6q5fpmQTuUSw9yAfL2oMrAcY1Rhd2VH2n8N5qRmRbsdwMKkCbX2RcQt1c3kTxnpXgJ6XawOanmF3G83su/m0TVxrDXdiOVo9QD7xQNECR88ra/f+ghDxOxUjN2dhZy004L/DgMutwrocmWa3jsmQGLrE+TcaVSjqXfRAZCwQkEYJsTj1XI8yN2W0ZZ0rnbc2WTqMEwIDAQAB";//没有秘钥时候使用行方公钥做AES加密

		// 加密流程
		try {
			System.out.println("待加密内容:\n" + content);
			secretContent = AESUtil.encrypt(content, appSecret);
			System.out.println("已加密内容:\n" + secretContent);
		} catch (Exception e) {
			e.printStackTrace();
		}
		secretContent = Base64.encodeBase64String(secretContent.getBytes());
		System.out.println("已加密并压缩base64内容（结果密文）:\n" + secretContent);

		// 解密流程
		secretContent = new String(Base64.decodeBase64(secretContent));
		System.out.println("解压base64后:\n" + secretContent);
		// 解密
		try {
			System.out.println("已解密内容:\n" + AESUtil.decrypt(secretContent, appSecret));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}