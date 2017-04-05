package form

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	Auto    = "v0.api.upyun.com"
	Telecom = "v1.api.upyun.com"
	Cnc     = "v2.api.upyun.com"
	Ctt     = "v3.api.upyun.com"
	Muti    = "m0.api.upyun.com"
)

const (
	OneM = int64(1024 * 1024)
)

type UpForm struct {
	client *http.Client
	sig    Signature
	bucket string
	ks     Signature
}

func NewUpForm(bucket string, ks Signature) *UpForm {
	return &UpForm{
		client: &http.Client{},
		bucket: bucket,
		ks:     ks,
	}
}

func (uf *UpForm) PostFile(filepath string, remotepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	return uf.PostData(file, remotepath)
}

func (uf *UpForm) PostData(file io.Reader, remotepath string) error {
	p, err := NewformPolicy(uf.bucket, remotepath, time.Now().Add(time.Minute*5).Unix(), uf.ks)
	if err != nil {
		return err
	}
	return uf.postData(Auto, file, p)
}

func (uf *UpForm) postData(server string, file io.Reader, p Policy) error {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, err := w.CreateFormFile("file", "file.data")
	if nil != err {
		return err
	}
	io.Copy(fw, file)

	fw, _ = w.CreateFormField("policy")
	fw.Write([]byte(p.Encode()))
	fw, _ = w.CreateFormField("signature")
	fw.Write([]byte(p.Signature()))
	w.Close()

	posturl := fmt.Sprintf("http://%s/%v", server, uf.bucket)
	rsp, err := uf.client.Post(posturl, w.FormDataContentType(), &b)
	if nil != err {
		return err
	}

	if http.StatusOK != rsp.StatusCode {
		return fmt.Errorf("Post File Data Failed: %v", rsp.StatusCode)
	}

	return nil
}

func (uf *UpForm) postForm(server string, p Policy) (io.ReadCloser, error) {
	param := url.Values{}
	param.Set("policy", p.Encode())
	param.Set("signature", p.Signature())
	posturl := fmt.Sprintf("http://%s/%v", server, uf.bucket)

	rsp, err := uf.client.PostForm(posturl, param)
	if nil != err {
		return nil, err
	}
	if http.StatusOK != rsp.StatusCode {
		bd, _ := ioutil.ReadAll(rsp.Body)
		fmt.Println(string(bd), uf, uf.bucket)
		return nil, fmt.Errorf(rsp.Status)
	}
	return rsp.Body, nil
}

type uploadStatus struct {
	SaveToken   string `json:"save_token"`  //分块上传索引key，下一步分块上传数据时必须携带本参数
	BucketName  string `json:"bucket_name"` //文件保存空间
	Blocks      int64  `json:"blocks"`      //文件分块数量
	Status      []int  `json:"status"`      //分块文件上传状态，true表示已完成上传，false表示分块未完成上传。数组索引表示分块序号，从0开始；
	ExpiredAt   int64  `json:"expired_at"`  //当前分块上传数据有效期，超过有效期之后数据将会被清理
	TokenSecret string `json:"token_secret"`
}

func (uf *UpForm) SlicePostFile(filepath string, remotepath string) error {
	file, err := os.Open(filepath)
	if nil != err {
		return err
	}
	defer file.Close()
	return uf.SlicePostData(file, remotepath)
}

func (uf *UpForm) SlicePostData(file io.Reader, remotepath string) error {
	var b bytes.Buffer
	fileSize, err := io.Copy(&b, file)
	if nil != err {
		return err
	}
	h := md5.New()
	copySize, err := io.Copy(h, bytes.NewReader(b.Bytes()))
	if nil != err {
		return err
	}
	if copySize != fileSize {
		return fmt.Errorf("io.Copy Length Error. Origin: %v bytes, Copyed: %v bytes", fileSize, copySize)
	}
	fileHash := fmt.Sprintf("%x", h.Sum(nil))

	fileBlocks := fileSize / OneM
	if fileSize > fileBlocks*OneM {
		fileBlocks += 1
	}
	expiration := time.Now().Add(time.Minute * 5).Unix()
	p, _ := NewMutiformPolicy(remotepath, expiration, fileBlocks, fileHash, fileSize, uf.ks)

	body, err := uf.postForm(Muti, p)
	if nil != err {
		return err
	}
	defer body.Close()

	data, err := ioutil.ReadAll(body)
	if nil != err {
		return err
	}

	var upstatus uploadStatus
	err = json.Unmarshal(data, &upstatus)
	if nil != err {
		return err
	}

	//Begin Post file slice
	offset := int64(0)
	for k, v := range upstatus.Status {
		if 2 != v {
			index := int64(k)
			bufferSize := OneM
			if (index+1)*OneM > fileSize {
				bufferSize = fileSize - index*OneM
			}
			data := make([]byte, bufferSize)
			br := bytes.NewReader(b.Bytes())
			rd, err := br.ReadAt(data, offset)
			if nil != err && io.EOF != err {
				return err
			}
			offset += int64(rd)

			if int64(rd) != bufferSize {
				return fmt.Errorf("Read Failed")
			}
			h := md5.New()
			h.Write(data)
			blockHash := fmt.Sprintf("%x", h.Sum(nil))
			bp := &mutiformPolicy{
				ks: &KeySignature{key: upstatus.TokenSecret},
				DefaultPolicy: DefaultPolicy{
					"save_token":  upstatus.SaveToken,
					"expiration":  upstatus.ExpiredAt,
					"block_index": index,
					"block_hash":  blockHash,
				},
			}
			err = uf.postData(Muti, bytes.NewReader(data), bp)
			if nil != err {
				return err
			}
		}
	}

	fp := &mutiformPolicy{
		ks: &KeySignature{key: upstatus.TokenSecret},
		DefaultPolicy: DefaultPolicy{
			"save_token": upstatus.SaveToken,
			"expiration": time.Now().Add(time.Minute * 5).Unix(),
		},
	}
	_, err = uf.postForm(Muti, fp)
	if nil != err {
		return err
	}
	return nil
}
