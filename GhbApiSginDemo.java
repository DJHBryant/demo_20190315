package com.ghbank.openapi.demo;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import com.ghbank.openapi.util.AESUtil;
import com.ghbank.openapi.util.RSAUtil;

import net.sf.json.JSONObject;


/**
 * 开放平台api网关调用demo
 * @author Thanos 2018-11-06
 *
 */
public class GhbApiSginDemo {
	
    public static final String CHARSET = "UTF-8";
	// 应用密钥: 通过api定时更新, 参照 AppSecretApplyDemo.java
    public static String appSecret = "wggSlAgEAAoIBAQCrh1qYykpLwg/CtPt";

	public static void main(String[] args) {
		try {
			// 私钥字符串: 密钥生成参照 RSAUtil.java
			String privateString = RSAUtil.privateString;
			// 私钥
			PrivateKey privateKey = RSAUtil.restorePrivateKey(Base64.decodeBase64(privateString));
			// 发送报文原文
			String requestMsg = "{\"header\":{\"requestTime\":\"20190306150201397\",\"signData\":\"\",\"charset\":\"UTF-8\",\"requestId\":\"20190306150201397400000\",\"appId\":\"10002009\"},\"body\":{\"randomStr\":\"mer07287643218969136314\",\"agentNo\":\"201703210000173\",\"sign\":\"53A337F980FF4556D47E50F192F77AFE\",\"signType\":\"MD5\",\"merchantInfo\":{\"remitD0\":\"2\",\"businessLicense\":\"320483000067847\",\"addressInfo\":{\"address\":\"华强北福田路58号\",\"province\":\"广东省\",\"city\":\"深圳市\",\"district\":\"福田区\"},\"remitT1\":\"0\",\"bankCardInfo\":{\"bankAccountName\":\"周瑾\",\"bankAccountAddress\":\"中国华兴银行莲花北支行\",\"bankAccountType\":\"1\",\"bankAccountLineNo\":\"102100000089\",\"bankAccountNo\":\"62122*******521428\"},\"servicePhone\":\"95188\",\"businessLicenseType\":\"NATIONAL_LEGAL\",\"fullName\":\"balabala巴辣香锅会展中心店\",\"shortName\":\"巴辣香锅\"},\"merchantNo\":\"201703210006450\"}}"; 
			// 组装请求报文
			requestMsg = getRequestMsg(requestMsg, privateKey, appSecret);
			System.out.println("发送报文: \n" + requestMsg);
			
			// 公钥字符串: 密钥生成参照 RSAUtil.java
			String publicKeyString = RSAUtil.publicStr; 
			// 公钥
			PublicKey publicKey = RSAUtil.restorePublicKey(Base64.decodeBase64(publicKeyString));
			// 解析返回报文
			String responseMsg = "{\n" +
	                "  \"body\": \"\",\n" +
	                "  \"header\": {\n" +
	                "    \"charset\": \"UTF-8\",\n" +
	                "    \"requestId\": \"1111111112\",\n" +
	                "    \"appId\": \"10016003\",\n" +
	                "    \"reserve\": \"\",\n" +
	                "    \"signType\": \"RSA\",\n" +
	                "    \"encryptType\": \"AES\",\n" +
	                "    \"responseId\": \"OPB01201903152014261000\",\n" +
	                "    \"errorCode\": \"3014\",\n" +
	                "    \"errorMsg\": \"当前接口无法及时响应,请稍后再试\",\n" +
	                "    \"subCode\": \"\",\n" +
	                "    \"subMsg\": \"\",\n" +
	                "    \"signData\": \"QjRCM0M3N0JBQkY4QkY2NjQ5Qzk2OEJBNUZENEVEMDU0NTlFNTA3RkZCMTEyODBGQzJCM0I2QkIxNkRFQTc2Nzc3QjVDMTM5Q0VGRDZBRjI4OUIwM0M5ODc2MjRDOTNFNUZCNjI4Nzk0NzNBNDM3MjMyOTdBOTU1MTI3NjhEMDRBMUYwNzdEMURCQUQyNTVCRjVENEVCNkU1RjAwQjdGMjA2QkEwOTQ2MDEyMzgxMjZDNkU0RTRDM0ZGMDVBQTg2NzE4REFDNTJGRTRBMEIzNzAwMzNCNkRCQ0Q1QTBCMDEyQUVERUQ0NDE0M0JFRjZFREI0QjdCMTM2MEUyMjkyNw==\",\n" +
	                "    \"responseTime\": \"20190315201428145\"\n" +
	                "  }\n" +
	                "}";
			responseMsg = getResponseMsg(responseMsg, publicKey, appSecret);
			System.out.println("响应报文: \n" + responseMsg);
			
			
			// 申请秘钥发送报文原文
			requestMsg = "{\"header\": {\"requestTime\": \"20190306150201397\",\"signData\": \"\",\"charset\": \"UTF-8\",\"requestId\": \"20190306150201397400000\",\"appId\": \"10023001\"},\"body\": \"\"}"; 
			// 申请秘钥组装请求报文
			requestMsg = getRequestMsg(requestMsg, privateKey, publicKey);
			System.out.println("申请秘钥发送报文: \n" + requestMsg);
			
			// 申请秘钥解析返回报文
			responseMsg  = "{\n" +
	                "  \"body\": \"RitgbIXQMSd84C5NRP3gZP7VVhf5VCKcGx/GSh6wOEZu9aCOsrDzH8oBCYUV/nk7iJdg8jMY9BAelNckCdHMC6dWS3hD6lSRrEZGm5mECHQkk/qFoGmxgaz+uQqB0fX8QiZ9fEo+NKJ4iOiLbuvXcLbJP2nEPFNV1iq5teJNPJzIxckj/L0r9bHsRLMbNoJbeILknUT8S9XfUl/mJuW0S2es4x12Z7MQknsqpIrAWbLfGhcONaXg1te/7qn9Hv2Bdt4eIpUWtS3QH54IPt3jn0q2rTZlwt7PI2IAZfpWxdLLYcLMdO0JH1hqF/KsghKAKvfRkm+l4OokB9hbc4mbIg==\",\n" +
	                "  \"header\": {\n" +
	                "    \"charset\": \"UTF-8\",\n" +
	                "    \"requestId\": \"1111111112\",\n" +
	                "    \"appId\": \"1QD00001\",\n" +
	                "    \"reserve\": \"\",\n" +
	                "    \"signType\": \"RSA\",\n" +
	                "    \"encryptType\": \"AES\",\n" +
	                "    \"responseId\": \"OPB01201903151909381000\",\n" +
	                "    \"signData\": \"MzgyQTNEN0UwQjc0OUZCQUNBQ0VGQ0I2MDA3M0ZEQ0QwNEIxQjlEQ0MyODZFMjFCMzM3NDMwMkNGOUNCQUU3RDUwRjJCRTZENkRDQjE4M0ZGQzI5RTZEMTcyNUIyOEE4MTM1RTFEM0U1MzRBMjQ3OTFERUFENTE3Qjc0OUI4Mzc3MEZFN0YwMzBEMjM1MUQ2NjAwMUY0M0U4MUVENUZGNDRDMTQzQkQyREMxQThDOUUzRjFFOTM4MEVCNkYzNzg2NTVDMEZDQUFGQTM2OTg3MjExRkYyMUMzNjg2NjNERUM2Mjg0NTU2N0YzNDBDNjk5QjNBMDcyMDA2QTNFNTY5Mg==\",\n" +
	                "    \"errorCode\": \"0000\",\n" +
	                "    \"errorMsg\": \"请求成功!\",\n" +
	                "    \"subCode\": \"0\",\n" +
	                "    \"subMsg\": \"\",\n" +
	                "    \"responseTime\": \"20190315190947169\"\n" +
	                "  }\n" +
	                "}";
			responseMsg = getResponseMsg(responseMsg, privateKey, publicKey);
			System.out.println("申请秘钥响应报文: \n" + responseMsg);
			

		} catch (Exception e) {
			e.printStackTrace();
		};
	}

	/**
	 * 组装请求报文
	 * @param msg
	 */
	public static String getRequestMsg(String msg, PrivateKey privateKey,String secret) {
		String privateString = RSAUtil.privateString;
		if(privateKey==null)
		{
			try {
				privateKey = RSAUtil.restorePrivateKey(Base64.decodeBase64(privateString));
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		// 待发送报文原文
		JSONObject requestJsonObj = JSONObject.fromObject(msg);
		// 报文头Json对象
		JSONObject headerJsonObject = requestJsonObj.getJSONObject("header");
		// 报文体字符串
		String bodyStr = requestJsonObj.getString("body");
		try {
			if(secret==null)
				secret = appSecret;
			// 对报文body数据进行AES加密
			bodyStr = AESUtil.encrypt(bodyStr, secret);
			// 对加密数据进行BASE64编码
			bodyStr = Base64.encodeBase64String(bodyStr.getBytes(CHARSET));
			// 替换原有body内容
			requestJsonObj.put("body", bodyStr);
			// 组装待签名报文：body+requestId+requestTime 
			String signData = bodyStr + headerJsonObject.getString("requestId") + headerJsonObject.getString("requestTime");
			// 待签名报文MD5加密
			signData = RSAUtil.MD5(signData);
			// RSA加密
			long startTime = System.currentTimeMillis();
			byte[] encodedText = RSAUtil.RSAEncode(privateKey, signData.getBytes("UTF-8"));
	        
	        //私钥签名后的数据 
	        signData = RSAUtil.byteArrayToHexString(encodedText);//报文头前面256位的私钥签名后的结果privateResult
			System.out.println("签名耗时: " + (System.currentTimeMillis()-startTime));
			// BASE64编码
			signData = Base64.encodeBase64String(signData.getBytes(CHARSET));
			// 为报文头参数signData赋值
			headerJsonObject.put("signData", signData);
			// 清空header里的signData
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return requestJsonObj.toString();
	}
	
	/**
	 * 解析响应报文
	 * @param sendMsg
	 */
	public static String getResponseMsg(String msg, PublicKey publicKey,String secret) {
		String publicKeyString = RSAUtil.publicStr;
		// 公钥
		if(publicKey==null)
		{
			publicKey = RSAUtil.restorePublicKey(Base64.decodeBase64(publicKeyString));
		}
		// 返回报文
		JSONObject responseMsgJsonObj = JSONObject.fromObject(msg);
		// 报文头Json对象
		JSONObject headerJsonObject = responseMsgJsonObj.getJSONObject("header");
		// 报文体字符串
		String bodyStr = responseMsgJsonObj.getString("body");
		try {
			// 组装待验证原文：body+responseId+responseTime+errorCode+errorMsg
			String originData = bodyStr + headerJsonObject.getString("requestId") + headerJsonObject.getString("responseId");
            if(bodyStr==null||"".equals(bodyStr))
            	originData = headerJsonObject.getString("requestId") + headerJsonObject.getString("responseId");
			// 组装待验证原文MD5加密
			originData = RSAUtil.MD5(originData);
			// 获取请求报文头header里的签名数据signData
			String signData = headerJsonObject.getString("signData");
			// 对signData进行Base64解密
			signData = new String(Base64.decodeBase64(signData.getBytes(CHARSET)));
			// RSA验签
		    // 需要自行比对验签解析完的MD5值 跟 组装待验证原文MD5做比对，一致表示验签成功，本案例不做校验
		    String signDataRsaDecode = RSAUtil.RSADecode(publicKey, RSAUtil.hexStringToByte(signData));
		    
			if(signDataRsaDecode==null || signData==null || originData==null) {
				System.out.println("RSA解密失败！！ ");
				return null;
			}
			// 对加报文体body密文进行BASE64解码
			bodyStr = new String(Base64.decodeBase64(bodyStr.getBytes(CHARSET)));
			// AES解密
			if(secret==null)
				secret = appSecret;
			bodyStr = AESUtil.decrypt(bodyStr, secret);
			// 替换原有body内容
			responseMsgJsonObj.put("body", bodyStr);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return responseMsgJsonObj.toString();
	}
	
	/**
	 * 秘钥申请组装请求报文
	 * @param msg
	 */
	public static String getRequestMsg(String msg, PrivateKey privateKey, PublicKey publicKey) {
		String publicKeyString = RSAUtil.publicStr;
		String privateString = RSAUtil.privateString;
		if(privateKey==null || publicKey==null)
		{
			try {
				privateKey = RSAUtil.restorePrivateKey(Base64.decodeBase64(privateString));
				publicKey = RSAUtil.restorePublicKey(Base64.decodeBase64(publicKeyString));
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		// 待发送报文原文
		JSONObject requestJsonObj = JSONObject.fromObject(msg);
		// 报文头Json对象
		JSONObject headerJsonObject = requestJsonObj.getJSONObject("header");
		// 报文体字符串
		String bodyStr = requestJsonObj.getString("body");
		try {
			// 对报文body数据进行AES加密并BASE64编码
			bodyStr = RSAUtil.encodeData(publicKey, bodyStr);
			// 替换原有body内容
			requestJsonObj.put("body", bodyStr);
			// 组装待签名报文：body+requestId+requestTime 
			String signData = bodyStr + headerJsonObject.getString("requestId") + headerJsonObject.getString("requestTime");
			// 待签名报文MD5加密
			signData = RSAUtil.MD5(signData);
			// RSA加密
			long startTime = System.currentTimeMillis();
			byte[] encodedText = RSAUtil.RSAEncode(privateKey, signData.getBytes("UTF-8"));
	        
	        //私钥签名后的数据 
	        signData = RSAUtil.byteArrayToHexString(encodedText);//报文头前面256位的私钥签名后的结果privateResult
			System.out.println("签名耗时: " + (System.currentTimeMillis()-startTime));
			// BASE64编码
			signData = Base64.encodeBase64String(signData.getBytes(CHARSET));
			// 为报文头参数signData赋值
			headerJsonObject.put("signData", signData);
			// 清空header里的signData
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return requestJsonObj.toString();
	}
	
	/**
	 * 秘钥申请解析响应报文
	 * @param sendMsg
	 */
	public static String getResponseMsg(String msg, PrivateKey privateKey, PublicKey publicKey) {
		String publicKeyString = RSAUtil.publicStr;
		String privateString = RSAUtil.privateString;
		if(privateKey==null || publicKey==null)
		{
			try {
				privateKey = RSAUtil.restorePrivateKey(Base64.decodeBase64(privateString));
				publicKey = RSAUtil.restorePublicKey(Base64.decodeBase64(publicKeyString));
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		// 返回报文
		JSONObject responseMsgJsonObj = JSONObject.fromObject(msg);
		// 报文头Json对象
		JSONObject headerJsonObject = responseMsgJsonObj.getJSONObject("header");
		// 报文体字符串
		String bodyStr = responseMsgJsonObj.getString("body");
		try {
			// 组装待验证原文：body+requestId+responseId+responseTime+errorCode+errorMsg
			String originData = bodyStr + headerJsonObject.getString("requestId") + headerJsonObject.getString("responseId");
          
			// 组装待验证原文MD5加密
			originData = RSAUtil.MD5(originData);
			// 获取请求报文头header里的签名数据signData
			String signData = headerJsonObject.getString("signData");
			// 对signData进行Base64解密
			signData = new String(Base64.decodeBase64(signData.getBytes(CHARSET)));
			// RSA验签
		    // 需要自行比对验签解析完的MD5值 跟 组装待验证原文MD5做比对，一致表示验签成功，本案例不做校验
		    String signDataRsaDecode = RSAUtil.RSADecode(publicKey, RSAUtil.hexStringToByte(signData));
			if(signDataRsaDecode==null || signData==null || originData==null) {
				System.out.println("RSA解密失败！！ ");
				return null;
			}
			// BASE64解码并AES解密
			bodyStr = RSAUtil.decodeData(privateKey, bodyStr);
			// 替换原有body内容
			responseMsgJsonObj.put("body", bodyStr);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return responseMsgJsonObj.toString();
	}
}
