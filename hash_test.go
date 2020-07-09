package goutil

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

var (
	data = []byte("hello,世界")
)

func TestCRC32(t *testing.T) {
	v := CRC32(data)
	if v != 1972257306 {
		t.Error("test fail")
	}
}

func TestHash(t *testing.T) {
	type args struct {
		algo      HashAlgo
		data      []byte
		rawOutput bool
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"md5",
			args{MD5, data, false},
			[]byte("c6b65ead773ff0516de556973080ec76"),
			false,
		},
		{
			"sha1",
			args{SHA1, data, false},
			[]byte("ffb5eccfcb365fc84a85fcb0291647eeefc83b30"),
			false,
		},
		{
			"sha224",
			args{SHA224, data, false},
			[]byte("2b04a4973d5638cdf32d38bd23373ce866363258a796bfa88162a8be"),
			false,
		},
		{
			"sha256",
			args{SHA256, data, false},
			[]byte("2aa2147e3bfbfdf4c8ff113d64ec7c49e145b9d49d6e7a1e78b2839b4cdca838"),
			false,
		},
		{
			"sha384",
			args{SHA384, data, false},
			[]byte("38c1ee4482f80378265356f416faa185d45b5be4cb6bd241b33495b545178c0f1a1a5d2551928ff164b8bbf1ed7bb810"),
			false,
		},
		{
			"sha512",
			args{SHA512, data, false},
			[]byte("fde7d6165db8095748180246dc5b828df233c959fe0abd78a0e409846de436c0f5f85e1e2d92736e2a6886ab8b2bb9734e55981e502b371a7411cdc0259c8347"),
			false,
		},
		{
			"sha512_224",
			args{SHA512_224, data, false},
			[]byte("b6edff7680c4c9d4c377448eae1d98758a328f80a0ec1806b584043d"),
			false,
		},
		{
			"sha512_256",
			args{SHA512_256, data, false},
			[]byte("d04cef58583daaed8994f8944d546ad5f390e5b1c329b1849d07cb72918131c1"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hash(tt.args.algo, tt.args.data, tt.args.rawOutput)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Hash() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashFile(t *testing.T) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	fn := f.Name()
	f.Write(data)
	f.Close()
	defer os.Remove(fn)
	t.Log("filename: ", fn)
	h, err := HashFile(MD5, fn, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(h))
}
