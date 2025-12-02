package cn.jzyunqi.common.third.sina.client;

import cn.jzyunqi.common.exception.BusinessException;
import cn.jzyunqi.common.feature.redis.Cache;
import cn.jzyunqi.common.feature.redis.RedisHelper;
import cn.jzyunqi.common.third.sina.enums.ImageSize;
import cn.jzyunqi.common.third.sina.model.CookieRedisDto;
import cn.jzyunqi.common.third.sina.model.PictureDto;
import cn.jzyunqi.common.third.sina.response.LoginRsp;
import cn.jzyunqi.common.third.sina.response.PreLoginRsp;
import cn.jzyunqi.common.third.sina.response.UploadRsp;
import cn.jzyunqi.common.utils.CollectionUtilPlus;
import cn.jzyunqi.common.utils.DigestUtilPlus;
import cn.jzyunqi.common.utils.RandomUtilPlus;
import cn.jzyunqi.common.utils.StringUtilPlus;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.net.URIBuilder;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.CRC32;

/**
 * @author wiiyaya
 * @date 2018/9/1.
 */
@Slf4j
public class SinaCookieClient {

    private static final Pattern IMAGE_PID_PATTERN = Pattern.compile("^[a-zA-Z0-9]{32}$");

    private static final Pattern IMAGE_URL_PATTERN = Pattern.compile("(https?://[a-z]{2}\\d{1}.sinaimg.cn/)("+Arrays.stream(ImageSize.values()).map(ImageSize::toString).collect(Collectors.joining("|"))+")(/([a-zA-Z0-9]{32}).(jpg|gif))");

    private static final String IMAGE_URL_HTTP = "http://ww%d.sinaimg.cn/%s/%s.%s";

    private static final String IMAGE_URL_HTTPS = "https://ws%d.sinaimg.cn/%s/%s.%s";

    private static final String WEIBO_COOKIE_KEY = "WEIBO_COOKIE";

    private String encryptUsername;

    private String password;

    private RestTemplate restTemplate;

    private RedisHelper redisHelper;

    private ObjectMapper objectMapper;

    public SinaCookieClient(String username, String password, RestTemplate restTemplate, RedisHelper redisHelper, ObjectMapper objectMapper) throws Exception {
        this.encryptUsername = DigestUtilPlus.Base64.encodeBase64String(URLEncoder.encode(username, StringUtilPlus.UTF_8_S).getBytes(StringUtilPlus.UTF_8_S));
        this.password = password;
        this.restTemplate = restTemplate;
        this.redisHelper = redisHelper;
        this.objectMapper = objectMapper;
    }

    /**
     * 登录新浪SSO
     */
    public LoginRsp loginSSO() throws BusinessException {
        PreLoginRsp preLoginRsp = preLogin();

        LoginRsp loginRsp;
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept", "*/*");
            headers.set("Accept-Encoding", "gzip, deflate, br");
            headers.set("Accept-Language", "zh-CN,zh;q=0.9");
            headers.set("Content-Type", "application/x-www-form-urlencoded");
            headers.set("Host", "login.sina.com.cn");
            headers.set("Referer", "https://login.sina.com.cn/signup/signin.php?entry=sso");
            headers.set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36");

            String waitEncrypt = preLoginRsp.getServertime() + "\t" + preLoginRsp.getNonce() + "\n" + password;

            String encryptPassword = DigestUtilPlus.RSA.encryptECBPKCS1Padding(
                    waitEncrypt.getBytes(),
                    new BigInteger(preLoginRsp.getPubkey(), 16),
                    new BigInteger("10001", 16),
                    Boolean.FALSE);
            URI loginUri = new URIBuilder("http://login.sina.com.cn/sso/login.php")
                    .addParameter("entry", "sso")
                    .addParameter("gateway", "1")
                    .addParameter("from", "")
                    .addParameter("savestate", "30")
                    .addParameter("useticket", "0")
                    .addParameter("pagerefer", "")
                    .addParameter("vsnf", "1")
                    .addParameter("su", encryptUsername)
                    .addParameter("service", "sso")
                    .addParameter("servertime", preLoginRsp.getServertime() + "")
                    .addParameter("nonce", preLoginRsp.getNonce())
                    .addParameter("pwencode", "rsa2")
                    .addParameter("rsakv", preLoginRsp.getRsakv())
                    .addParameter("sp", encryptPassword)
                    .addParameter("sr", "1366*768")
                    .addParameter("encoding", StringUtilPlus.UTF_8_S)
                    .addParameter("cdult", "3")
                    .addParameter("domain", "sina.com.cn")
                    .addParameter("prelt", String.valueOf(RandomUtilPlus.Number.randomInt(100, 1000)))
                    .addParameter("returntype", "TEXT")
                    .build();

            RequestEntity requestEntity = new RequestEntity(headers, HttpMethod.POST, loginUri);
            ResponseEntity<LoginRsp> responseEntity = restTemplate.exchange(requestEntity, LoginRsp.class);

            loginRsp = Optional.ofNullable(responseEntity.getBody()).orElse(new LoginRsp());
            List<String> cookieList = responseEntity.getHeaders().get("Set-Cookie");
            if (CollectionUtilPlus.Collection.isNotEmpty(cookieList)) {
                loginRsp.setCookies(cookieList.stream().collect(Collectors.joining("; ")));
            }
        } catch (Exception e) {
            log.error("======SinaCookieHelper loginSSO login error:", e);
            throw new BusinessException("common_error_sina_login_sso_error");
        }

        if ("0".equals(loginRsp.getRetcode())) {
            return loginRsp;
        } else {
            log.error("======SinaCookieHelper loginSSO 200 error[]", loginRsp.getRetcode());
            throw new BusinessException("common_error_sina_login_sso_failed");
        }
    }

    /**
     * 登录新浪微博weibo.com
     */
    public List<String> loginWeibo(Cache cache) throws BusinessException {
        CookieRedisDto cookieRedisDto = (CookieRedisDto) redisHelper.vGet(cache, WEIBO_COOKIE_KEY);
        if (cookieRedisDto != null && LocalDateTime.now().isBefore(cookieRedisDto.getExpireTime())) {
            return cookieRedisDto.getCookieList();
        }

        LoginRsp loginRsp = loginSSO();
        for (String url : loginSSO().getCrossDomainUrlList()) {
            if (url.contains("weibo.com")) {
                try {
                    HttpHeaders headers = new HttpHeaders();
                    headers.set("Accept", "*/*");
                    headers.set("Accept-Encoding", "gzip, deflate, br");
                    headers.set("Accept-Language", "zh-CN,zh;q=0.9");
                    headers.set("Content-Type", "application/x-www-form-urlencoded");
                    headers.set("Host", "login.sina.com.cn");
                    headers.set("Referer", "https://login.sina.com.cn/crossdomain2.php?action=login&r=https%3A%2F%2Flogin.sina.com.cn%2F");
                    headers.set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36");

                    URI loginWeiboUri = new URIBuilder(url + "&callback=sinaSSOController.doCrossDomainCallBack&scriptId=ssoscript0&client=ssologin.js(v1.4.19)&_=" + System.currentTimeMillis()).build();
                    RequestEntity requestEntity = new RequestEntity(headers, HttpMethod.GET, loginWeiboUri);
                    ResponseEntity<String> responseEntity = restTemplate.exchange(requestEntity, String.class);

                    List<String> cookieList = responseEntity.getHeaders().get("Set-Cookie");
                    if (CollectionUtilPlus.Collection.isNotEmpty(cookieList)) {
                        cookieRedisDto = new CookieRedisDto();
                        cookieRedisDto.setCookieList(new ArrayList<>(cookieList)); //获取到的凭证
                        cookieRedisDto.setExpireTime(LocalDateTime.now().plusDays(1)); //凭证有效时间，单位：1天
                        redisHelper.vPut(cache, WEIBO_COOKIE_KEY, cookieRedisDto);

                        return cookieList;
                    } else {
                        log.error("======SinaCookieHelper loginWeibo login 200 error:[]", responseEntity.getBody());
                    }
                } catch (Exception e) {
                    log.error("======SinaCookieHelper loginWeibo login error:", e);
                    throw new BusinessException("common_error_sina_login_weibo_error");
                }
            }
        }
        log.error("======SinaCookieHelper loginWeibo login not found error");
        throw new BusinessException("common_error_sina_login_weibo_error");
    }

    /**
     * 上传文件至微博
     */
    public List<PictureDto> uploadToWeibo(Cache cache, List<Resource> resourceList) throws BusinessException {
        String uploadBody;
        try {
            URI materialAddUri = new URIBuilder("http://picupload.service.weibo.com/interface/pic_upload.php").build();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.set("Cookie", loginWeibo(cache).stream().collect(Collectors.joining("; ")));

            MultiValueMap<String, Object> params = new LinkedMultiValueMap<>();
            int i = 1;
            for (Resource resource : resourceList) {
                params.add("pic" + i, resource);
                i++;
            }

            RequestEntity<MultiValueMap<String, Object>> requestEntity = new RequestEntity<>(params, headers, HttpMethod.POST, materialAddUri);
            ResponseEntity<String> responseEntity = restTemplate.exchange(requestEntity, String.class);
            uploadBody = Optional.ofNullable(responseEntity.getBody()).orElse(StringUtilPlus.EMPTY);
        } catch (Exception e) {
            log.error("======SinaCookieHelper upload other error:", e);
            throw new BusinessException("common_error_sina_upload_add_error");
        }

        try {
            UploadRsp uploadRsp = objectMapper.readValue(StringUtilPlus.replaceAll(uploadBody, "([\\s\\S]*)<\\/script>", ""), UploadRsp.class);
            if ("A000006".equals(uploadRsp.getCode())) {
                List<PictureDto> pictureDtoList = new ArrayList<>(uploadRsp.getData().getPics().values());
                pictureDtoList.forEach(this::preparePictureImages);
                return pictureDtoList;
            } else {
                log.error("======SinaCookieHelper upload 200 error[][]:", uploadRsp.getCode(), uploadRsp);
                throw new BusinessException("common_error_sina_upload_failed");
            }
        } catch (Exception e) {
            log.error("======SinaCookieHelper upload 200 error:", e);
            throw new BusinessException("common_error_sina_upload_failed");
        }
    }

    /**
     * 获取图片地址
     */
    public PictureDto preparePictureImages(String pid) throws BusinessException {
        Matcher pidMatcher = IMAGE_PID_PATTERN.matcher(pid);
        PictureDto pictureDto = new PictureDto();
        if(pidMatcher.matches()){
            pictureDto.setPid(pid);
            return preparePictureImages(pictureDto);
        }else{
            String imageSize = Arrays.stream(ImageSize.values()).map(ImageSize::toString).collect(Collectors.joining("|"));
            Matcher urlMatcher = IMAGE_URL_PATTERN.matcher(pid);
            if (urlMatcher.find()) {
                pictureDto.setPid(urlMatcher.group(4));
                return preparePictureImages(pictureDto);
            }else{
                throw new BusinessException("common_error_get_image_url_failed");
            }
        }
    }

    /**
     * 获取图片地址
     */
    public PictureDto preparePictureImages(PictureDto pictureDto){
        CRC32 crc32 = new CRC32();
        crc32.update(pictureDto.getPid().getBytes());

        long site = ((crc32.getValue() & 3) + 1);
        String imgType = (pictureDto.getPid().charAt(21) == 'g' ? "gif" : "jpg");

        Map<String, String> httpUrlMap = Arrays.stream(ImageSize.values()).collect(Collectors.toMap(ImageSize::toString, imageSize -> String.format(IMAGE_URL_HTTP, site, imageSize, pictureDto.getPid(), imgType)));
        Map<String, String> httpsUrlMap = Arrays.stream(ImageSize.values()).collect(Collectors.toMap(ImageSize::toString, imageSize -> String.format(IMAGE_URL_HTTPS, site, imageSize, pictureDto.getPid(), imgType)));

        pictureDto.setHttpUrlMap(httpUrlMap);
        pictureDto.setHttpsUrlMap(httpsUrlMap);

        return pictureDto;
    }

    /**
     * 预登陆接口，获取必要数据
     */
    private PreLoginRsp preLogin() throws BusinessException {
        String preLoginBody;
        try {
            URI preLoginUri = new URIBuilder("http://login.sina.com.cn/sso/prelogin.php")
                    .addParameter("entry", "weibo")
                    .addParameter("callback", "sinaSSOController.preloginCallBack")
                    .addParameter("su", encryptUsername)
                    .addParameter("rsakt", "mod")
                    .addParameter("checkpin", "1")
                    .addParameter("client", "ssologin.js(v1.4.18)")
                    .addParameter("_", String.valueOf(System.currentTimeMillis()))
                    .build();
            RequestEntity requestEntity = new RequestEntity(HttpMethod.GET, preLoginUri);
            ResponseEntity<String> responseEntity = restTemplate.exchange(requestEntity, String.class);
            preLoginBody = Optional.ofNullable(responseEntity.getBody()).orElse(StringUtilPlus.EMPTY);
        } catch (Exception e) {
            log.error("======SinaCookieHelper preLogin other error:", e);
            throw new BusinessException("common_error_sina_pre_login_error");
        }

        try {
            Matcher preLoginMatcher = Pattern.compile("\\((.*?)\\)").matcher(preLoginBody);
            preLoginMatcher.find();
            return objectMapper.readValue(preLoginMatcher.group(1), PreLoginRsp.class);
        } catch (Exception e) {
            log.error("======SinaCookieHelper preLogin 200 error:", e);
            throw new BusinessException("common_error_sina_pre_login_failed");
        }
    }
}
