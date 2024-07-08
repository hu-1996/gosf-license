package license

import (
	"cmp"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/hu-1996/gosf-license/consts"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/spf13/viper"
)

// GenerateParam 生成证书参数
type GenerateParam struct {
	Overwrite            bool                   `json:"overwrite" yaml:"overwrite"`                       // 是否覆盖License
	Subject              string                 `json:"subject" yaml:"subject"`                           // 证书subject
	PrivateAlias         string                 `json:"privateAlias" yaml:"privateAlias"`                 // 密钥别称
	KeyPass              string                 `json:"keyPass" yaml:"keyPass"`                           // 密钥密码（需要妥善保管，不能让使用者知道）
	StorePass            string                 `json:"storePass" yaml:"storePass"`                       // 访问秘钥库的密码
	LicensePath          string                 `json:"licensePath" yaml:"licensePath"`                   // 证书生成路径
	PrivateKeysStorePath string                 `json:"privateKeysStorePath" yaml:"privateKeysStorePath"` // 密钥库存储路径
	IssuedTime           time.Time              `json:"issuedTime" yaml:"issuedTime"`                     // 证书生效时间
	ExpiryTime           time.Time              `json:"expiryTime" yaml:"expiryTime"`                     // 证书失效时间
	ConsumerType         string                 `json:"consumerType" yaml:"consumerType"`                 // 用户类型
	ConsumerAmount       int                    `json:"consumerAmount" yaml:"consumerAmount"`             // 用户数量
	Description          string                 `json:"description" yaml:"description"`                   // 描述信息
	LicenseCheckModel    *CheckModel            `json:"licenseCheckModel" yaml:"licenseCheckModel"`       // 服务器硬件校验信息
	Extra                map[string]interface{} `json:"extra" yaml:"extra"`                               // 额外的信息
}

type CheckModel struct {
	IpAddress       []string `json:"ipAddress" yaml:"ipAddress"`             // 可被允许的IP地址
	MacAddress      []string `json:"macAddress" yaml:"macAddress"`           // 可被允许的MAC地址
	CpuSerial       []string `json:"cpuSerial" yaml:"cpuSerial"`             // 可被允许的CPU序列号
	MainBoardSerial string   `json:"mainBoardSerial" yaml:"mainBoardSerial"` // 可被允许的主板序列号
	//NodeAddress     []string `json:"nodeAddress" yaml:"nodeAddress"`         // 可被允许的Node MAC地址
	//GPUID           []string `json:"GPUID" yaml:"GPUID"`                     // 可被允许的GPU ID地址
}

func (c *GenerateParam) ReadYaml(path string) error {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		return err
	}
	if err := v.Unmarshal(&c); err != nil {
		return err
	}
	return nil
}

// Generate 生成软件证书许可
func Generate(param *GenerateParam) error {
	err := param.prepareGenerateParam()
	if err != nil {
		return err
	}

	err = checkLicensePath(param.LicensePath)
	if err != nil {
		return err
	}

	err = generateCer(param)
	if err != nil {
		return err
	}

	privateKey, _, err := loadKeyStore(param.PrivateKeysStorePath, param.StorePass, param.PrivateAlias, param.KeyPass)
	if err != nil {
		return err
	}

	// 加密许可证
	err = generateLicense(param, param.LicensePath, privateKey, param.Overwrite)
	if err != nil {
		log.Fatalf("failed to encrypt pkg: %v", err)
	}

	return nil
}

func (p *GenerateParam) prepareGenerateParam() error {
	p.Subject = cmp.Or(p.Subject, consts.Subject)
	p.PrivateAlias = cmp.Or(p.PrivateAlias, consts.PrivateAlias)
	p.KeyPass = cmp.Or(p.KeyPass, consts.KeyPass)
	p.StorePass = cmp.Or(p.StorePass, consts.StorePass)

	if p.LicensePath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}

		p.LicensePath = filepath.Join(home, consts.WorkSpace)
	}
	p.PrivateKeysStorePath = cmp.Or(p.PrivateKeysStorePath, filepath.Join(p.LicensePath, consts.PrivateKeys))

	if p.IssuedTime.IsZero() {
		p.IssuedTime = time.Now().In(time.Local)
	}

	if p.ExpiryTime.IsZero() {
		return errors.New("ExpiryTime未设置")
	}

	if p.IssuedTime.After(p.ExpiryTime) {
		return errors.New("ExpiryTime早于IssuedTime")
	}

	p.ConsumerType = cmp.Or(p.ConsumerType, consts.ConsumerType)
	p.ConsumerAmount = cmp.Or(p.ConsumerAmount, consts.ConsumerAmount)
	p.Description = cmp.Or(p.Description, consts.Description)

	return nil
}

func checkLicensePath(licensePath string) error {
	stat, err := os.Stat(licensePath)
	if err != nil {
		if os.IsNotExist(err) { // 目录不存在
			log.Printf("path: %s is not exist, preparing to create", licensePath)
			err = os.MkdirAll(licensePath, os.ModePerm) // 递归创建目录
			if err != nil {
				return err
			}

			fmt.Printf("path: %s created", licensePath)
		} else {
			return err
		}
	} else if !stat.IsDir() {
		return fmt.Errorf("output path: %s is not a directory", licensePath)
	}

	return nil
}

func checkFileExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func generateCer(param *GenerateParam) error {
	if !param.Overwrite {
		exist, err := checkFileExist(param.PrivateKeysStorePath)
		if err != nil {
			return err
		}

		if exist {
			fmt.Printf("%s exist", param.PrivateKeysStorePath)
			return nil
		}
	}

	// 生成 RSA 私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}

	// 创建证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{param.Subject},
		},
		NotBefore:             param.IssuedTime,
		NotAfter:              param.ExpiryTime,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 使用模板和私钥生成自签名证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("failed to create certificate: %v", err)
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
		return err
	}

	// 保存 keystore 到文件
	keystoreFile, err := os.Create(param.PrivateKeysStorePath)
	if err != nil {
		log.Fatalf("failed to create keystore file: %v", err)
	}
	defer keystoreFile.Close()

	if err := ks.Store(keystoreFile, []byte(param.StorePass)); err != nil {
		log.Fatalf("failed to store keystore: %v", err)
	}

	fmt.Println("Keystore created successfully, path: " + param.PrivateKeysStorePath)

	return nil
}

func loadKeyStore(keystorePath, keystorePassword, alias, entryPassword string) (*rsa.PrivateKey, *x509.Certificate, error) {
	// 打开并读取 keystore 文件
	ksFile, err := os.Open(keystorePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open keystore file: %v", err)
	}
	defer ksFile.Close()

	// 解析 keystore 文件
	ks := keystore.New()
	if err := ks.Load(ksFile, []byte(keystorePassword)); err != nil {
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

func generateLicense(param *GenerateParam, licensePath string, privateKey *rsa.PrivateKey, overwrite bool) error {
	// 将结构体序列化为 YAML
	yamlData, err := yaml.Marshal(param)
	if err != nil {
		return fmt.Errorf("write YAML err: %s", err)
	}

	err = createLicense(yamlData, licensePath, overwrite)
	if err != nil {
		return err
	}

	err = createLicenseSig(yamlData, licensePath, privateKey, overwrite)
	if err != nil {
		return err
	}

	return nil
}

func createLicense(data []byte, licensePath string, overwrite bool) error {
	licenseFilePath := filepath.Join(licensePath, consts.LicenseFile)
	if !overwrite {
		exist, err := checkFileExist(licenseFilePath)
		if err != nil {
			return err
		}

		if exist {
			fmt.Printf("%s exist", licenseFilePath)
			return nil
		}
	}

	err := writeYaml(licenseFilePath, data)
	if err != nil {
		return err
	}

	fmt.Println("pkg created successfully")
	return nil
}

func createLicenseSig(data []byte, licensePath string, privateKey *rsa.PrivateKey, overwrite bool) error {
	licenseFilePath := filepath.Join(licensePath, consts.LicenseSigFile)
	if !overwrite {
		exist, err := checkFileExist(licenseFilePath)
		if err != nil {
			return err
		}

		if exist {
			fmt.Printf("%s exist", licenseFilePath)
			return nil
		}
	}

	encryptData, err := encryptLicense(data, privateKey)
	if err != nil {
		return err
	}

	err = writeYaml(licenseFilePath, encryptData)
	if err != nil {
		return err
	}

	fmt.Println("pkg.sig created successfully")
	return nil
}

func encryptLicense(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to hash pkg data: %v", err)
	}
	encryptedData, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt pkg: %v", err)
	}
	return encryptedData, nil
}

func Example() error {
	serial, _ := GetCPUSerial()
	boardSerial, _ := GetMainBoardSerial()
	ipAddress, _ := GetIpAddress()
	macAddress, _ := GetMacAddress()
	nodes, _ := getK8sNodes()

	config := GenerateParam{
		Overwrite:            false,
		Subject:              "sf",
		PrivateAlias:         consts.PrivateAlias,
		KeyPass:              consts.KeyPass,
		StorePass:            consts.StorePass,
		LicensePath:          consts.HomeDir,
		PrivateKeysStorePath: "",
		IssuedTime:           time.Now(),
		ExpiryTime:           time.Now().Add(10 * 366 * 24 * time.Hour),
		ConsumerType:         consts.ConsumerType,
		ConsumerAmount:       consts.ConsumerAmount,
		Description:          consts.Description,
		LicenseCheckModel: &CheckModel{
			CpuSerial:       serial,
			MainBoardSerial: boardSerial,
			IpAddress:       ipAddress,
			MacAddress:      macAddress,
			//NodeAddress:     nodes,
		},
		Extra: map[string]interface{}{
			"nodes": nodes,
		},
	}

	// 将结构体序列化为 YAML
	yamlData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("write YAML err: %s", err)
	}

	err = writeYaml("config.yaml", yamlData)
	if err != nil {
		return err
	}

	return nil
}

func writeYaml(name string, data []byte) error {
	// 创建或打开文件
	file, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("creating YAML err: %s", err)
	}
	defer file.Close()

	// 将 YAML 数据写入文件
	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("writing YAML err: %s", err)
	}

	fmt.Println("YAML data written to file successfully, path: " + name)
	return nil
}
