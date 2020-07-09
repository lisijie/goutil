package goutil

import (
	"testing"
)

func TestAesEncrypt(t *testing.T) {
	text := []byte("hello world")
	key := []byte("secret key")

	cipherText, err := AesEncrypt(text, key)
	if err != nil {
		t.Error(err)
	}

	text2, err2 := AesDecrypt(cipherText, key)
	if err2 != nil {
		t.Error(err2)
	}

	if string(text2) != string(text) {
		t.Errorf("AES加密解密测试失败: %v != %v", string(text2), string(text))
	}
}
