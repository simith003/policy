package cn.com.nike.policy.bean;

import java.util.List;
import java.util.Map;

public class WebVulnData {
	
	/**
	 * 其他漏洞利用信息
	 */
	private List<Map<String, String>> result;
	
	/**
	 * shell
	 */
	private WebShell shell;
	
	public List<Map<String, String>> getResult() {
		return result;
	}
	public void setResult(List<Map<String, String>> result) {
		this.result = result;
	}
	public WebShell getShell() {
		return shell;
	}
	public void setShell(WebShell shell) {
		this.shell = shell;
	}
	
	
}
