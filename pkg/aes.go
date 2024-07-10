package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/hu-1996/gosf-license/consts"
	"github.com/hu-1996/gosf-license/pkg/store"
	"io"
)

var _ License = (*Aes)(nil)

type Aes struct {
	store store.Store
}

func NewAes(store store.Store) *Aes {
	return &Aes{
		store: store,
	}
}

func (l *Aes) Generate(param *GenerateParam) error {
	err := param.prepareGenerateParam()
	if err != nil {
		return err
	}

	err = l.generateLicense(param)
	if err != nil {
		return err
	}
	return nil
}

func (l *Aes) generateLicense(param *GenerateParam) error {
	// 将结构体序列化为 YAML
	data, err := json.Marshal(param.prepareLicenseContent())
	if err != nil {
		return fmt.Errorf("write json err: %s", err)
	}

	err = l.createLicense(param.LicenseName, data, param.Metadata[consts.Overwrite].(bool))
	if err != nil {
		return err
	}

	err = l.createLicenseSig(param.LicenseSigName, data, param.Metadata[consts.Overwrite].(bool))
	if err != nil {
		return err
	}

	return nil
}

func (l *Aes) createLicense(licenseName string, data []byte, overwrite bool) error {
	return l.store.Store(licenseName, data, overwrite)
}

func (l *Aes) createLicenseSig(licenseName string, data []byte, overwrite bool) error {
	encryptData, err := aesEncrypt(string(data))
	if err != nil {
		return err
	}

	return l.store.Store(licenseName, []byte(encryptData), overwrite)
}

func (l *Aes) LocalValidate(param *ValidateParam) error {
	if param.LicenseCheckModel == nil {
		serial, _ := GetCPUSerial()
		boardSerial, _ := GetMainBoardSerial()
		ipAddress, _ := GetIpAddress()
		macAddress, _ := GetMacAddress()
		param.LicenseCheckModel = &CheckModel{
			IpAddress:       ipAddress,
			MacAddress:      macAddress,
			CpuSerial:       serial,
			MainBoardSerial: boardSerial,
		}
	}

	err := l.Validate(param)
	if err != nil {
		return err
	}

	return nil
}

func (l *Aes) Validate(param *ValidateParam) error {
	err := param.prepareVerifyParam()
	if err != nil {
		return err
	}

	// 验证许可证
	licenseData, err := l.validateLicense(param.LicenseName, param.LicenseSigName)
	if err != nil {
		return err
	}

	err = param.Validate(licenseData)
	if err != nil {
		return err
	}

	fmt.Println("validate valid！")
	return nil
}

func (l *Aes) validateLicense(licenseName, licenseSigName string) (*LicenseContent, error) {
	LicenseNameData, err := l.store.Load(licenseName)
	if err != nil {
		return nil, err
	}

	if len(LicenseNameData) == 0 {
		return nil, fmt.Errorf("license content is empty, please check the environment variables")
	}

	LicenseSigNameData, err := l.store.Load(licenseSigName)
	if err != nil {
		return nil, err
	}

	decryptData, err := aesDecrypt(string(LicenseSigNameData))
	if err != nil {
		return nil, err
	}

	if decryptData != string(LicenseNameData) {
		return nil, fmt.Errorf("failed to validate license")
	}

	licenseData := new(LicenseContent)
	err = json.Unmarshal(LicenseNameData, licenseData)
	if err != nil {
		return nil, err
	}
	return licenseData, nil
}

func aesEncrypt(text string) (string, error) {
	plaintext := []byte(text)

	block, err := aes.NewCipher([]byte(consts.KeyPass))
	if err != nil {
		return "", err
	}

	// IV needs to be unique, but does not have to be kept secret.
	// You can add it to the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext), nil
}

func aesDecrypt(ciphertext string) (string, error) {
	// Decode the ciphertext from hex string
	ciphertextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(consts.KeyPass))
	if err != nil {
		return "", err
	}

	// IV is just the first block of ciphertext
	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

	return string(ciphertextBytes), nil
}
