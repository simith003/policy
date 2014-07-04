package cn.com.nike.policy.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;

/**
 * @category 策略工具类
 * @author nike
 * @version 1.0
 */
public class PolicyUtil {

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
}
