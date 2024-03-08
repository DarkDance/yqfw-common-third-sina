package cn.jzyunqi.common.third.sina.response;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;
import java.util.List;

/**
 * @author wiiyaya
 * @date 2018/8/31.
 */
@Getter
@Setter
@ToString
public class LoginRsp implements Serializable {
    private static final long serialVersionUID = -1177189594046201645L;

    /**
     * 返回代码，0为成功
     */
    private String retcode;

    /**
     * 用户唯一id
     */
    private String uid;

    /**
     * 用户昵称
     */
    private String nick;

    /**
     * 登录cookies
     */
    private String cookies;

    /**
     * 其它可登陆网站
     */
    private List<String> crossDomainUrlList;

}
