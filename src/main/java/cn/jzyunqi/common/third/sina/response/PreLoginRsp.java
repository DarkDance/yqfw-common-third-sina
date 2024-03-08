package cn.jzyunqi.common.third.sina.response;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

/**
 * @author wiiyaya
 * @date 2018/8/31.
 */
@Getter
@Setter
@ToString
public class PreLoginRsp implements Serializable {
    private static final long serialVersionUID = -7598788440656916343L;

    /**
     * 返回代码，0为成功
     */
    private String retcode;

    /**
     * 随机数
     */
    private String nonce;

    /**
     * 公钥
     */
    private String pubkey;

    /**
     * 服务器时间
     */
    private String servertime;

    /**
     * RSA加密向量
     */
    private String rsakv;

}
