package form

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
)

/*
from: http://docs.upyun.com/api/form_api/

### 表单 API 参数

|         参数         | 必选 |                                                 说明                                                |
|----------------------|------|-----------------------------------------------------------------------------------------------------|
| bucket               | 是   | 保存所上传的文件的 UPYUN 空间名                                                                     |
| save-key             | 是   | 保存路径，如: '/path/to/file.ext'，可用占位符 [\[注1\]](#note1)                      |
| expiration           | 是   | 请求的过期时间，UNIX 时间戳（秒）                                                                   |
| allow-file-type      | 否   | 文件类型限制，制定允许上传的文件扩展名                                                              |
| content-length-range | 否   | 文件大小限制，格式：`min,max`，单位：字节，如 `102400,1024000`，允许上传 100Kb～1Mb 的文件          |
| content-md5          | 否   | 所上传的文件的 MD5 校验值，UPYUN 根据此来校验文件上传是否正确                                       |
| content-secret       | 否   | 原图访问密钥 [\[注2\]](#note2)                                                 |
| content-type         | 否   | UPYUN 默认根据扩展名判断，手动指定可提高精确性                                                      |
| image-width-range    | 否   | 图片宽度限制，格式：`min,max`，单位：像素，如 `0,1024`，允许上传宽度为 0～1024px 之间               |
| image-height-range   | 否   | 图片高度限制，格式：`min,max`，单位：像素，如 `0,1024`，允许上传高度在 0～1024px 之间               |
| notify-url           | 否   | 异步通知 URL，见 [\[通知规则\]](#notify_return)                                                      |
| return-url           | 否   | 同步通知 URL，见 [\[通知规则\]](#notify_return)                                                      |
| x-gmkerl-thumbnail   | 否   | 缩略图版本名称，仅支持图片类空间，可搭配其他 `x-gmkerl-*` 参数使用 [\[注3\]](#note3) |
| x-gmkerl-type        | 否   | 缩略类型 [\[注4\]](#note4)                                                           |
| x-gmkerl-value       | 否   | 缩略类型对应的参数值 [\[注4\]](#note5)                                               |
| x-gmkerl-quality     | 否   | **默认 95**缩略图压缩质量                                                                           |
| x-gmkerl-unsharp     | 否   | **默认锐化（true）**是否进行锐化处理                                                                |
| x-gmkerl-rotate      | 否   | 图片旋转（顺时针），可选：`auto`，`90`，`180`，`270` 之一                                           |
| x-gmkerl-crop        | 否   | 图片裁剪，格式：`x,y,width,height`，均需为正整型                                                    |
| x-gmkerl-exif-switch | 否   | 是否保留 exif 信息，仅在搭配 `x-gmkerl-crop`，`x-gmkerl-type`，`x-gmkerl-thumbnail` 时有效。        |
| ext-param            | 否   | 额外参数，UTF-8 编码，并小于 255 个字符 [\[注5\]](#note5)                            |
*/

type Policy interface {
	Set(string, interface{})
	Get(string) interface{}

	Encode() string
	StrEncode() string
	UrlEncode() string

	Decode(jsonstr string) error

	Signature() string
}

type Signature interface {
	SigBolocks(Policy) string
	SigFile(Policy) string
}

type DefaultPolicy map[string]interface{}

func (dp *DefaultPolicy) Get(key string) interface{} {
	return (*dp)[key]
}

func (dp *DefaultPolicy) Set(key string, value interface{}) {
	(*dp)[key] = value
}

func (dp *DefaultPolicy) UrlEncode() string {
	uv := url.Values{}
	for k, v := range *dp {
		uv.Set(k, fmt.Sprint(v))
	}
	return uv.Encode()
}

func (dp *DefaultPolicy) StrEncode() string {
	sortKeys := []string{}
	for k, _ := range *dp {
		sortKeys = append(sortKeys, k)
	}
	sort.Strings(sortKeys)
	dictString := ""
	for _, v := range sortKeys {
		dictString += v + fmt.Sprint(dp.Get(v))
	}
	return dictString
}

func (dp *DefaultPolicy) Encode() string {
	j, _ := json.Marshal(dp)
	return base64.StdEncoding.EncodeToString(j)
}

func (dp *DefaultPolicy) Decode(jsonstr string) error {
	return json.Unmarshal([]byte(jsonstr), dp)
}

type formPolicy struct {
	ks Signature
	DefaultPolicy
}

func NewformPolicy(bucket string, savekey string, expiration int64, ks Signature) (Policy, error) {
	return &formPolicy{
		ks: ks,
		DefaultPolicy: DefaultPolicy{
			"bucket":     bucket,
			"save-key":   savekey,
			"expiration": expiration,
		},
	}, nil
}

func (p *formPolicy) Signature() string {
	return p.ks.SigFile(p)
}

type mutiformPolicy struct {
	ks Signature
	DefaultPolicy
}

func NewMutiformPolicy(path string, expiration int64, file_blocks int64, file_hash string, file_size int64, ks Signature) (Policy, error) {
	return &mutiformPolicy{
		ks: ks,
		DefaultPolicy: DefaultPolicy{
			"path":        path,
			"expiration":  expiration,
			"file_blocks": file_blocks,
			"file_hash":   file_hash,
			"file_size":   file_size,
		},
	}, nil
}

func (p *mutiformPolicy) Signature() string {
	return p.ks.SigBolocks(p)
}

type KeySignature struct {
	key string
}

func NewKeySignature(key string) Signature {
	return &KeySignature{key: key}
}

func (s *KeySignature) SigBolocks(p Policy) string {
	sig, _ := SumStrMd5(p.StrEncode() + s.key)
	return sig
}

func (s *KeySignature) SigFile(p Policy) string {
	sig, _ := SumStrMd5(p.Encode() + "&" + s.key)
	return sig
}
