package cn.com.nike.policy.base;

/**
 * 策略基本信息
 * @author nike
 * @version 1.0
 */
public abstract class PolicyInfo {
	
	/**
	 * 策略名称
	 */
	protected String POLICYNAME = "";
	
	/**
	 * 策略id
	 * 包括一些证书编号 cve 等等
	 */
	protected String POLICYID = "";
	
	/**
	 * 策略描述
	 */
	protected String POLICYDESCRIPTION = "";
	
	/**
	 * 漏洞发生时间
	 */
	protected String POLICYTIME = "";
	
	/**
	 * 策略针对的厂商
	 */
	protected String POLICYCOMPANY = "";
	
	protected String PAYLOAD_CHECK = "";
	protected String PAYLOAD_EXPLOIT = "";
	
}
