package license

import (
	"cmp"
	"errors"
	"fmt"
	"github.com/hu-1996/gosf-license/consts"
	"github.com/hu-1996/gosf-license/pkg/store"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"slices"
	"time"
)

type License interface {
	Generate(param *GenerateParam) error
	LocalValidate(param *ValidateParam) error
	Validate(param *ValidateParam) error
}

type LicenseContent struct {
	EncryptionMethod  string                 `json:"encryptionMethod" yaml:"encryptionMethod"`   // 加密方式
	StoreMethod       string                 `json:"storeMethod" yaml:"storeMethod"`             // 存储方式
	Subject           string                 `json:"subject" yaml:"subject"`                     // 证书subject
	Issued            time.Time              `json:"issued" yaml:"issued"`                       // 证书生成时间
	NotBefore         time.Time              `json:"notBefore" yaml:"notBefore"`                 // 证书生效时间
	NotAfter          time.Time              `json:"notAfter" yaml:"notAfter"`                   // 证书失效时间
	ConsumerType      string                 `json:"consumerType" yaml:"consumerType"`           // 用户类型
	ConsumerAmount    int                    `json:"consumerAmount" yaml:"consumerAmount"`       // 用户数量
	Description       string                 `json:"description" yaml:"description"`             // 描述信息
	LicenseCheckModel *CheckModel            `json:"licenseCheckModel" yaml:"licenseCheckModel"` // 服务器硬件校验信息
	Extra             map[string]interface{} `json:"extra" yaml:"extra"`                         // 额外的信息
}

// ExampleParam 生成config
type ExampleParam struct {
	EncryptionMethod     string                 `json:"encryptionMethod" yaml:"encryptionMethod"`                   // 加密方式
	StoreMethod          string                 `json:"storeMethod" yaml:"storeMethod"`                             // 存储方式
	LicenseName          string                 `json:"licenseName" yaml:"licenseName"`                             // 证书生成名称
	LicenseSigName       string                 `json:"licenseSigName" yaml:"licenseSigName"`                       // sig证书生成名称
	PrivateKeysStoreName string                 `json:"privateKeysStoreName" yaml:"privateKeysStoreName,omitempty"` // 密钥库存储名称
	Extra                map[string]interface{} `json:"extra" yaml:"extra"`                                         // 额外的校验信息
}

// GenerateParam 生成证书参数
type GenerateParam struct {
	Overwrite            bool                   `json:"overwrite" yaml:"overwrite"`                                 // 是否覆盖License
	EncryptionMethod     string                 `json:"encryptionMethod" yaml:"encryptionMethod"`                   // 加密方式
	StoreMethod          string                 `json:"storeMethod" yaml:"storeMethod"`                             // 存储方式
	Subject              string                 `json:"subject" yaml:"subject"`                                     // 证书subject
	PrivateAlias         string                 `json:"privateAlias" yaml:"privateAlias,omitempty"`                 // 密钥别称
	KeyPass              string                 `json:"keyPass" yaml:"keyPass"`                                     // 密钥密码（需要妥善保管，不能让使用者知道）
	StorePass            string                 `json:"storePass" yaml:"storePass,omitempty"`                       // 访问秘钥库的密码
	LicenseName          string                 `json:"licenseName" yaml:"licenseName"`                             // 证书生成名称
	LicenseSigName       string                 `json:"licenseSigName" yaml:"licenseSigName"`                       // sig证书生成名称
	PrivateKeysStoreName string                 `json:"privateKeysStoreName" yaml:"privateKeysStoreName,omitempty"` // 密钥库存储名称
	Issued               time.Time              `json:"issued" yaml:"issued"`                                       // 证书生成时间
	NotBefore            time.Time              `json:"notBefore" yaml:"notBefore"`                                 // 证书生效时间
	NotAfter             time.Time              `json:"notAfter" yaml:"notAfter"`                                   // 证书失效时间
	ConsumerType         string                 `json:"consumerType" yaml:"consumerType"`                           // 用户类型
	ConsumerAmount       int                    `json:"consumerAmount" yaml:"consumerAmount"`                       // 用户数量
	Description          string                 `json:"description" yaml:"description"`                             // 描述信息
	LicenseCheckModel    *CheckModel            `json:"licenseCheckModel" yaml:"licenseCheckModel"`                 // 服务器硬件校验信息
	Extra                map[string]interface{} `json:"extra" yaml:"extra"`                                         // 额外的信息
}

type CheckModel struct {
	IpAddress       []string `json:"ipAddress" yaml:"ipAddress"`             // 可被允许的IP地址
	MacAddress      []string `json:"macAddress" yaml:"macAddress"`           // 可被允许的MAC地址
	CpuSerial       []string `json:"cpuSerial" yaml:"cpuSerial"`             // 可被允许的CPU序列号
	MainBoardSerial string   `json:"mainBoardSerial" yaml:"mainBoardSerial"` // 可被允许的主板序列号
	//NodeAddress     []string `json:"nodeAddress" yaml:"nodeAddress"`         // 可被允许的Node MAC地址
	//GPUID           []string `json:"GPUID" yaml:"GPUID"`                     // 可被允许的GPU ID地址
}

type ValidateParam struct {
	EncryptionMethod     string                                                         // 加密方式
	StoreMethod          string                                                         // 存储方式
	PrivateAlias         string                                                         // 密钥别称
	KeyPass              string                                                         // 密钥密码（需要妥善保管，不能让使用者知道）
	StorePass            string                                                         // 访问秘钥库的密码
	LicenseName          string                                                         // 证书生成名称
	LicenseSigName       string                                                         // sig证书生成名称
	PrivateKeysStoreName string                                                         // 密钥库存储名称
	NotBefore            time.Time                                                      // 证书生效时间
	NotAfter             time.Time                                                      // 证书失效时间
	ConsumerAmount       int                                                            // 用户数量
	LicenseCheckModel    *CheckModel                                                    // 服务器硬件校验信息
	Extra                map[string]interface{}                                         // 额外的校验信息
	ExtraValidateFunc    func(licenseExtra, validateExtra map[string]interface{}) error // 额外的校验函数
}

func Example(param *ExampleParam) error {
	serial, _ := GetCPUSerial()
	boardSerial, _ := GetMainBoardSerial()
	ipAddress, _ := GetIpAddress()
	macAddress, _ := GetMacAddress()

	config := GenerateParam{
		Overwrite:            false,
		EncryptionMethod:     param.EncryptionMethod,
		StoreMethod:          param.StoreMethod,
		Subject:              "sf",
		PrivateAlias:         consts.PrivateAlias,
		KeyPass:              consts.KeyPass,
		StorePass:            consts.StorePass,
		LicenseName:          param.LicenseName,
		LicenseSigName:       param.LicenseSigName,
		PrivateKeysStoreName: param.PrivateKeysStoreName,
		Issued:               time.Now(),
		NotBefore:            time.Now(),
		NotAfter:             time.Now().AddDate(99, 0, 0),
		ConsumerType:         consts.ConsumerType,
		ConsumerAmount:       consts.ConsumerAmount,
		Description:          consts.Description,
		LicenseCheckModel: &CheckModel{
			CpuSerial:       serial,
			MainBoardSerial: boardSerial,
			IpAddress:       ipAddress,
			MacAddress:      macAddress,
		},
		Extra: param.Extra,
	}

	// 将结构体序列化为 YAML
	yamlData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("write YAML err: %s", err)
	}

	err = new(store.DiskStore).Store("config.yaml", yamlData, false)
	if err != nil {
		return err
	}

	return nil
}

func (p *GenerateParam) prepareGenerateParam() error {
	p.Subject = cmp.Or(p.Subject, consts.Subject)
	p.KeyPass = cmp.Or(p.KeyPass, consts.KeyPass)
	if p.EncryptionMethod == consts.PrivateKey {
		p.PrivateAlias = cmp.Or(p.PrivateAlias, consts.PrivateAlias)
		p.StorePass = cmp.Or(p.StorePass, consts.StorePass)
	}

	if p.LicenseName == "" {
		return errors.New("licenseName must not be empty")
	}

	if p.LicenseSigName == "" {
		return errors.New("licenseSigName must not be empty")
	}

	if p.EncryptionMethod == consts.PrivateKey && p.PrivateKeysStoreName == "" {
		return errors.New("when the encryption method is privateKey, PrivateKeysStoreName must not be empty")
	}

	if p.Issued.IsZero() {
		p.Issued = time.Now().In(time.Local)
	}

	if p.NotBefore.IsZero() {
		return errors.New("NotBefore must not be empty")
	}

	if p.NotAfter.IsZero() {
		return errors.New("NotAfter must not be empty")
	}

	if p.Issued.After(p.NotAfter) {
		return errors.New("NotAfter is earlier than Issued")
	}

	if p.NotBefore.After(p.NotAfter) {
		return errors.New("NotAfter is earlier than NotBefore")
	}

	p.ConsumerType = cmp.Or(p.ConsumerType, consts.ConsumerType)
	p.ConsumerAmount = cmp.Or(p.ConsumerAmount, consts.ConsumerAmount)
	p.Description = cmp.Or(p.Description, consts.Description)
	return nil
}

func (p *ValidateParam) prepareVerifyParam() error {
	p.KeyPass = cmp.Or(p.KeyPass, consts.KeyPass)
	if p.EncryptionMethod == consts.PrivateKey {
		p.PrivateAlias = cmp.Or(p.PrivateAlias, consts.PrivateAlias)
		p.StorePass = cmp.Or(p.StorePass, consts.StorePass)
	}
	return nil
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

func (c *LicenseContent) ReadYaml(path string) error {
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

func (params *ValidateParam) Validate(licenseData *LicenseContent) error {
	if params.NotBefore.Before(licenseData.NotBefore) {
		return fmt.Errorf("license certificate not yet in force，start time: %s", licenseData.NotBefore.String())
	}

	if params.NotAfter.After(licenseData.NotAfter) {
		return fmt.Errorf("license certificate expired，expiry time: %s", licenseData.NotAfter.String())
	}

	// 验证ConsumerAmount
	if params.ConsumerAmount > licenseData.ConsumerAmount {
		return fmt.Errorf("number of users over%d", licenseData.ConsumerAmount)
	}

	// 验证cpu
	if len(params.LicenseCheckModel.CpuSerial) > 0 {
		for _, cpu := range params.LicenseCheckModel.CpuSerial {
			if !slices.Contains(licenseData.LicenseCheckModel.CpuSerial, cpu) {
				return fmt.Errorf("cpu[%s] unauthorized", cpu)
			}
		}
	}

	// 验证主板
	if params.LicenseCheckModel.MainBoardSerial != "" && params.LicenseCheckModel.MainBoardSerial != licenseData.LicenseCheckModel.MainBoardSerial {
		return fmt.Errorf("main board[%s] unauthorized", params.LicenseCheckModel.MainBoardSerial)
	}

	// 验证ipAddress
	for _, ip := range params.LicenseCheckModel.IpAddress {
		if !slices.Contains(licenseData.LicenseCheckModel.IpAddress, ip) {
			return fmt.Errorf("ip[%s] unauthorized", ip)
		}
	}

	// 验证macAddress
	for _, macAddr := range params.LicenseCheckModel.MacAddress {
		if !slices.Contains(licenseData.LicenseCheckModel.MacAddress, macAddr) {
			return fmt.Errorf("mac address[%s] unauthorized", macAddr)
		}
	}

	// 验证extra
	if params.ExtraValidateFunc != nil {
		err := params.ExtraValidateFunc(licenseData.Extra, params.Extra)
		if err != nil {
			return err
		}
	}
	return nil
}
