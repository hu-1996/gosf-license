package license

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hu-1996/gosf-license/consts"
	"gopkg.in/yaml.v3"
	"math/big"
	"time"

	"github.com/hu-1996/gosf-license/pkg/store"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

var _ License = (*PrivateKey)(nil)

type PrivateKey struct {
	store store.Store
}

func NewPrivateKey(store store.Store) *PrivateKey {
	return &PrivateKey{
		store: store,
	}
}

// Generate 生成软件证书许可
func (l *PrivateKey) Generate(param *GenerateParam) error {
	err := param.prepareGenerateParam()
	if err != nil {
		return err
	}

	privateKey, err := l.generateCer(param)
	if err != nil {
		return err
	}

	if privateKey == nil {
		pk, _, err := l.loadKeyStore(param.PrivateKeyName, param.StorePass, param.PrivateAlias, param.KeyPass)
		if err != nil {
			return err
		}

		privateKey = pk
	}

	// 加密许可证
	err = l.generateLicense(param, privateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt license: %s", err)
	}

	return nil
}

// generateCer 目前只支持带io.Writer和io.Reader的store，env store不支持
func (l *PrivateKey) generateCer(param *GenerateParam) (*rsa.PrivateKey, error) {
	// 保存 keystore 到文件
	writer, err := l.store.Writer(param.PrivateKeyName)
	if err != nil {
		return nil, err
	}
	if writer == nil {
		return nil, errors.New("failed to create keystore file, io.Writer is nil")
	}
	defer writer.Close()

	if !param.Metadata[consts.Overwrite].(bool) {
		exist, err := l.store.Exist(param.PrivateKeyName)
		if err != nil {
			return nil, err
		}

		if exist {
			fmt.Printf("%s exist\n", param.PrivateKeyName)
			return nil, nil
		}
	}

	// 生成 RSA 私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// 创建证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{param.Subject},
		},
		NotBefore:             param.NotBefore,
		NotAfter:              param.NotAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 使用模板和私钥生成自签名证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// 将证书编码为 PEM 格式
	_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 将私钥编码为 PEM 格式
	_ = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// 创建 keystore
	ks := keystore.New()

	// 将证书和私钥添加到 keystore
	alias := param.PrivateAlias
	password := []byte(param.KeyPass)
	entry := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   x509.MarshalPKCS1PrivateKey(privateKey),
		CertificateChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: certDER,
			},
		},
	}
	err = ks.SetPrivateKeyEntry(alias, entry, password)
	if err != nil {
		return nil, err
	}

	if err := ks.Store(writer, []byte(param.StorePass)); err != nil {
		return nil, fmt.Errorf("failed to store keystore: %v", err)
	}

	fmt.Println("Keystore created successfully, path: " + param.PrivateKeyName)
	return privateKey, nil
}

// loadKeyStore 目前只支持带io.Writer和io.Reader的store，env store不支持
func (l *PrivateKey) loadKeyStore(keystorePath, keystorePassword, alias, entryPassword string) (*rsa.PrivateKey, *x509.Certificate, error) {
	// 打开并读取 keystore 文件
	reader, err := l.store.Reader(keystorePath)
	if err != nil {
		return nil, nil, err
	}
	if reader == nil {
		return nil, nil, errors.New("failed to create keystore file, io.Reader is nil")
	}
	defer reader.Close()

	// 解析 keystore 文件
	ks := keystore.New()
	if err := ks.Load(reader, []byte(keystorePassword)); err != nil {
		return nil, nil, fmt.Errorf("failed to load keystore: %v", err)
	}

	// 获取特定 alias 的私钥条目
	entry, err := ks.GetPrivateKeyEntry(alias, []byte(entryPassword))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get private key entry: %v", err)
	}

	// 解析私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(entry.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// 解析证书
	cert, err := x509.ParseCertificate(entry.CertificateChain[0].Content)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return privateKey, cert, nil
}

func (l *PrivateKey) generateLicense(param *GenerateParam, privateKey *rsa.PrivateKey) error {
	// 将结构体序列化为 YAML
	yamlData, err := yaml.Marshal(param.prepareLicenseContent())
	if err != nil {
		return fmt.Errorf("write YAML err: %s", err)
	}

	err = l.createLicense(param.LicenseName, yamlData, param.Metadata[consts.Overwrite].(bool))
	if err != nil {
		return err
	}

	err = l.createLicenseSig(param.LicenseSigName, yamlData, privateKey, param.Metadata[consts.Overwrite].(bool))
	if err != nil {
		return err
	}

	return nil
}

func (l *PrivateKey) createLicense(licenseName string, data []byte, overwrite bool) error {
	return l.store.Store(licenseName, data, overwrite)
}

func (l *PrivateKey) createLicenseSig(licenseName string, data []byte, privateKey *rsa.PrivateKey, overwrite bool) error {
	encryptData, err := encryptLicense(data, privateKey)
	if err != nil {
		return err
	}

	return l.store.Store(licenseName, encryptData, overwrite)
}

func encryptLicense(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to hash license data: %v", err)
	}
	encryptedData, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt license: %v", err)
	}
	return encryptedData, nil
}

// LocalValidate 验证软件证书许可，会自动补全本机的CPU，IP，MAC address并与License进行验证
func (l *PrivateKey) LocalValidate(param *ValidateParam) error {
	if param.LicenseCheckModel == nil {
		serial, _ := GetCPUSerial()
		boardSerial, _ := GetBaseBoardSerial()
		ipAddress, _ := GetIpAddress()
		macAddress, _ := GetMacAddress()
		param.LicenseCheckModel = &CheckModel{
			IpAddress:       ipAddress,
			MacAddress:      macAddress,
			CpuSerial:       serial,
			BaseBoardSerial: []string{boardSerial},
		}
	}

	err := l.Validate(param)
	if err != nil {
		return err
	}

	return nil
}

// Validate 验证软件证书许可，不会自动补全本机的CPU，IP，MAC address，请自行补充信息
func (l *PrivateKey) Validate(param *ValidateParam) error {
	err := param.prepareVerifyParam()
	if err != nil {
		return err
	}

	_, cert, err := l.loadKeyStore(param.PrivateKeyName, param.StorePass, param.PrivateAlias, param.KeyPass)
	if err != nil {
		return err
	}

	// 验证许可证
	licenseData, err := l.validateLicense(param.LicenseName, param.LicenseSigName, cert)
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

func (l *PrivateKey) validateLicense(licenseName, licenseSigName string, cert *x509.Certificate) (*LicenseContent, error) {
	LicenseNameData, err := l.store.Load(licenseName)
	if err != nil {
		return nil, err
	}

	LicenseSigNameData, err := l.store.Load(licenseSigName)
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	_, err = hash.Write(LicenseNameData)
	if err != nil {
		return nil, fmt.Errorf("failed to hash license data: %v", err)
	}

	err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash.Sum(nil), LicenseSigNameData)
	if err != nil {
		return nil, fmt.Errorf("failed to validate license: %v", err)
	}

	licenseData := new(LicenseContent)
	err = licenseData.ReadYaml(licenseName)
	if err != nil {
		return nil, err
	}

	return licenseData, nil
}
