package cn.jzyunqi.common.third.sina.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;
import java.util.Map;

/**
 * @author wiiyaya
 * @date 2018/9/2.
 */
@Getter
@Setter
@ToString
public class PictureDto implements Serializable {
    private static final long serialVersionUID = 3288565320219815308L;

    private String pid;

    private String name;

    private Integer ret;

    private Integer width;

    private Integer height;

    private Integer size;

    private Map<String, String> httpUrlMap;

    private Map<String, String> httpsUrlMap;
}
