package cn.jzyunqi.common.third.sina.constant;

import cn.jzyunqi.common.support.spring.redis.Cache;
import cn.jzyunqi.common.third.sina.model.CookieRedisDto;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Duration;

/**
 * @author wiiyaya
 * @since 2026/5/2
 */
@Getter
@AllArgsConstructor
public enum SinaCache implements Cache {

    THIRD_SINA_COOKIE_V(Duration.ZERO, Boolean.FALSE, CookieRedisDto.class),
    ;

    private final Duration expiration;

    private final Boolean autoRenew;

    private final Object valueType;
}
