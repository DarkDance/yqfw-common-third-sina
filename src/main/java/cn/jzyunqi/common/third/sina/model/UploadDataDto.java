package cn.jzyunqi.common.third.sina.model;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Map;

/**
 * @author wiiyaya
 * @date 2018/9/2.
 */
@Getter
@Setter
public class UploadDataDto implements Serializable {
    private static final long serialVersionUID = 4010972333605033968L;

    private Integer count;

    private String data;

    private Map<String, PictureDto> pics;
}
