package cn.jzyunqi.common.third.sina.model;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

/**
 * @author wiiyaya
 * @date 2018/9/1.
 */
@Getter
@Setter
public class CookieRedisDto implements Serializable {
    private static final long serialVersionUID = 7267393846734365451L;

    /**
     * 授权cookie
     */
    private List<String> cookieList;

    /**
     * 过期时间
     */
    private LocalDateTime expireTime;
}
