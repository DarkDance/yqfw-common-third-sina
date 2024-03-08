package cn.jzyunqi.common.third.sina.response;

import cn.jzyunqi.common.third.sina.model.UploadDataDto;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

/**
 * @author wiiyaya
 * @date 2018/9/2.
 */
@Getter
@Setter
@ToString
public class UploadRsp implements Serializable {
    private static final long serialVersionUID = 9044461121651986492L;

    private String code;

    private UploadDataDto data;
}
