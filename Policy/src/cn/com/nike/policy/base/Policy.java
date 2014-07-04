package cn.com.nike.policy.base;

import java.util.Map;

import org.apache.log4j.Logger;

import cn.com.nike.policy.bean.WebVulnData;

/**
 * @category 策略命名程序_版本_漏洞类型
 * @author nike
 * @version 1.0
 */
public interface Policy {
	
	public Logger log = Logger.getLogger(Policy.class);
	
	/**
	 * 设置漏洞需要的参数
	 * @param parameter
	 */
	public void setParameter(Map<String, Object> parameters);
	
	/**
	 * 初步检测
	 * @return 漏洞存在成功返回true 不存在返回false
	 */
	public boolean check() throws Exception;
	
	/**
	 * 利用成功返回结果
	 * @return 返回webvuln
	 */
	public WebVulnData exploit() throws Exception;
	
	
}
