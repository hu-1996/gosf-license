package license

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hu-1996/gosf-license/consts"
	"github.com/hu-1996/gosf-license/pkg/store"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"
)

type License interface {
	Generate(param *GenerateParam) error
	LocalValidate(param *ValidateParam) error
	Validate(param *ValidateParam) error
	GetLicenseContent(name string) (LicenseContent, error)
}

type LicenseContent struct {
	Subject        string                 `json:"subject" yaml:"subject"`                                                                  // 证书subject
	Issued         time.Time              `json:"issued" yaml:"issued"`                                                                    // 证书生成时间
	NotBefore      time.Time              `json:"not_before" yaml:"not_before" mapstructure:"not_before"`                                  // 证书生效时间
	NotAfter       time.Time              `json:"not_after" yaml:"not_after" mapstructure:"not_after"`                                     // 证书失效时间
	ConsumerType   string                 `json:"consumer_type" yaml:"consumer_type" mapstructure:"consumer_type"`                         // 用户类型
	ConsumerAmount int                    `json:"consumer_amount" yaml:"consumer_amount" mapstructure:"consumer_amount"`                   // 用户数量
	Description    string                 `json:"description" yaml:"description"`                                                          // 描述信息
	CheckModel     *CheckModel            `json:"check_model,omitempty" yaml:"check_model,omitempty" mapstructure:"check_model,omitempty"` // 服务器硬件校验信息
	Metadata       map[string]interface{} `json:"metadata" yaml:"metadata"`                                                                // 元数据
	Extra          map[string]interface{} `json:"extra,omitempty" yaml:"extra,omitempty"`                                                  // 额外的信息
}

// ExampleParam 生成config
type ExampleParam struct {
	LicenseName    string                 `json:"license_name" yaml:"license_name" mapstructure:"license_name"`                                           // 证书生成名称
	LicenseSigName string                 `json:"license_sig_name" yaml:"license_sig_name" mapstructure:"license_sig_name"`                               // sig证书生成名称
	PrivateKeyName string                 `json:"private_key_name,omitempty" yaml:"private_key_name,omitempty" mapstructure:"private_key_name,omitempty"` // 密钥库存储名称
	Metadata       map[string]interface{} `json:"metadata" yaml:"metadata"`                                                                               // 元数据
	Extra          map[string]interface{} `json:"extra,omitempty" yaml:"extra,omitempty"`                                                                 // 额外的校验信息
}

// GenerateParam 生成证书参数
type GenerateParam struct {
	Subject        string                 `json:"subject" yaml:"subject"`                                                                                 // 证书subject
	PrivateAlias   string                 `json:"private_alias" yaml:"private_alias,omitempty" mapstructure:"private_alias,omitempty"`                    // 密钥别称
	KeyPass        string                 `json:"key_pass" yaml:"key_pass" mapstructure:"key_pass"`                                                       // 密钥密码（需要妥善保管，不能让使用者知道）
	StorePass      string                 `json:"store_pass,omitempty" yaml:"store_pass,omitempty" mapstructure:"store_pass,omitempty"`                   // 访问秘钥库的密码
	LicenseName    string                 `json:"license_name" yaml:"license_name" mapstructure:"license_name"`                                           // 证书生成名称
	LicenseSigName string                 `json:"license_sig_name" yaml:"license_sig_name" mapstructure:"license_sig_name"`                               // sig证书生成名称
	PrivateKeyName string                 `json:"private_key_name,omitempty" yaml:"private_key_name,omitempty" mapstructure:"private_key_name,omitempty"` // 密钥库存储名称
	Issued         time.Time              `json:"issued" yaml:"issued"`                                                                                   // 证书生成时间
	NotBefore      time.Time              `json:"not_before" yaml:"not_before" mapstructure:"not_before"`                                                 // 证书生效时间
	NotAfter       time.Time              `json:"not_after" yaml:"not_after" mapstructure:"not_after"`                                                    // 证书失效时间
	ConsumerType   string                 `json:"consumer_type" yaml:"consumer_type" mapstructure:"consumer_type"`                                        // 用户类型
	ConsumerAmount int                    `json:"consumer_amount" yaml:"consumer_amount" mapstructure:"consumer_amount"`                                  // 用户数量
	Description    string                 `json:"description" yaml:"description"`                                                                         // 描述信息
	Metadata       map[string]interface{} `json:"metadata" yaml:"metadata"`                                                                               // 元数据
	CheckModel     *CheckModel            `json:"check_model,omitempty" yaml:"check_model,omitempty" mapstructure:"check_model,omitempty"`                // 服务器硬件校验信息
	Extra          map[string]interface{} `json:"extra,omitempty" yaml:"extra,omitempty"`                                                                 // 额外的信息
}

type CheckModel struct {
	IpAddress       []string `json:"ip_address" yaml:"ip_address" mapstructure:"ip_address"`                      // 可被允许的IP地址
	MacAddress      []string `json:"mac_address" yaml:"mac_address" mapstructure:"mac_address"`                   // 可被允许的MAC地址
	CpuSerial       []string `json:"cpu_serial" yaml:"cpu_serial" mapstructure:"cpu_serial"`                      // 可被允许的CPU序列号
	BaseBoardSerial []string `json:"base_board_serial" yaml:"base_board_serial" mapstructure:"base_board_serial"` // 可被允许的主板序列号
}

type ValidateParam struct {
	PrivateAlias      string                                                         // 密钥别称
	KeyPass           string                                                         // 密钥密码（需要妥善保管，不能让使用者知道）
	StorePass         string                                                         // 访问秘钥库的密码
	LicenseName       string                                                         // 证书生成名称
	LicenseSigName    string                                                         // sig证书生成名称
	PrivateKeyName    string                                                         // 密钥库存储名称
	NotBefore         time.Time                                                      // 证书生效时间
	NotAfter          time.Time                                                      // 证书失效时间
	ConsumerAmount    int                                                            // 用户数量
	Metadata          map[string]interface{}                                         // 元数据
	LicenseCheckModel *CheckModel                                                    // 服务器硬件校验信息
	Extra             map[string]interface{}                                         // 额外的校验信息
	ExtraValidateFunc func(licenseExtra, validateExtra map[string]interface{}) error // 额外的校验函数
}

func Example(param *ExampleParam) error {
	serial, _ := GetCPUSerial()
	boardSerial, _ := GetBaseBoardSerial()
	ipAddress, _ := GetIpAddress()
	macAddress, _ := GetMacAddress()

	config := GenerateParam{
		Subject:        "sf",
		PrivateAlias:   consts.PrivateAlias,
		KeyPass:        consts.KeyPass,
		StorePass:      consts.StorePass,
		LicenseName:    param.LicenseName,
		LicenseSigName: param.LicenseSigName,
		PrivateKeyName: param.PrivateKeyName,
		Issued:         time.Now(),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(99, 0, 0),
		ConsumerType:   consts.ConsumerType,
		ConsumerAmount: consts.ConsumerAmount,
		Description:    consts.Description,
		Metadata:       param.Metadata,
	}

	switch param.Metadata[consts.LicenseType].(string) {
	case consts.Kubernetes:
		config.Extra = param.Extra
	default:
		config.CheckModel = &CheckModel{
			CpuSerial:       serial,
			BaseBoardSerial: []string{boardSerial},
			IpAddress:       ipAddress,
			MacAddress:      macAddress,
		}
		config.Extra = param.Extra
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
	if p.Metadata[consts.EncryptionMethod].(string) == consts.PrivateKey {
		p.PrivateAlias = cmp.Or(p.PrivateAlias, consts.PrivateAlias)
		p.StorePass = cmp.Or(p.StorePass, consts.StorePass)
	}

	if p.LicenseName == "" {
		return errors.New("licenseName must not be empty")
	}

	if p.LicenseSigName == "" {
		return errors.New("licenseSigName must not be empty")
	}

	if p.Metadata[consts.EncryptionMethod].(string) == consts.PrivateKey && p.PrivateKeyName == "" {
		return errors.New("when the encryption method is privateKey, PrivateKeyName must not be empty")
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
	if p.Metadata[consts.EncryptionMethod].(string) == consts.PrivateKey {
		p.PrivateAlias = cmp.Or(p.PrivateAlias, consts.PrivateAlias)
		p.StorePass = cmp.Or(p.StorePass, consts.StorePass)
	}
	return nil
}

func (param *GenerateParam) prepareLicenseContent() *LicenseContent {
	content := &LicenseContent{
		Subject:        param.Subject,
		Issued:         param.Issued,
		NotBefore:      param.NotBefore,
		NotAfter:       param.NotAfter,
		ConsumerType:   param.ConsumerType,
		ConsumerAmount: param.ConsumerAmount,
		Description:    param.Description,
		Metadata:       param.Metadata,
	}
	switch param.Metadata[consts.LicenseType].(string) {
	case consts.Kubernetes:
		content.Extra = param.Extra
		delete(content.Extra, consts.ValidateNodes)
		delete(content.Extra, consts.ValidateGPUs)
	default:
		content.CheckModel = param.CheckModel
		content.Extra = param.Extra
	}

	return content
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
	for _, cpu := range params.LicenseCheckModel.CpuSerial {
		if !slices.Contains(licenseData.CheckModel.CpuSerial, cpu) {
			return fmt.Errorf("cpu[%s] unauthorized", cpu)
		}
	}

	// 验证主板
	for _, baseBoard := range params.LicenseCheckModel.BaseBoardSerial {
		if !slices.Contains(licenseData.CheckModel.BaseBoardSerial, baseBoard) {
			return fmt.Errorf("main board[%s] unauthorized", baseBoard)
		}
	}

	// 验证ipAddress
	for _, ip := range params.LicenseCheckModel.IpAddress {
		if !slices.Contains(licenseData.CheckModel.IpAddress, ip) {
			return fmt.Errorf("ip[%s] unauthorized", ip)
		}
	}

	// 验证macAddress
	for _, macAddr := range params.LicenseCheckModel.MacAddress {
		if !slices.Contains(licenseData.CheckModel.MacAddress, macAddr) {
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

func (params *ValidateParam) SwitchStore() (store.Store, error) {
	switch params.Metadata[consts.StoreMethod].(string) {
	case consts.DiskStore:
		if params.LicenseName == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			params.LicenseName = filepath.Join(home, consts.WorkSpace, consts.LicenseName)
		}

		if params.LicenseSigName == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			params.LicenseSigName = filepath.Join(home, consts.WorkSpace, consts.LicenseSigName)
		}

		if params.PrivateKeyName == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			params.PrivateKeyName = filepath.Join(home, consts.WorkSpace, consts.PrivateKeys)
		}

		return new(store.DiskStore), nil
	case consts.EnvStore:
		params.LicenseName = cmp.Or(params.LicenseName, consts.LicenseEnv)
		params.LicenseSigName = cmp.Or(params.LicenseSigName, consts.LicenseSigEnv)
		return new(store.EnvStore), nil
	default:
		return nil, errors.New("unknown store method")
	}
}

// NewLicense 只在example时使用
func (params *ValidateParam) NewLicense() (License, error) {
	encryptionType := params.Metadata[consts.EncryptionMethod].(string)
	var l License
	switch encryptionType {
	case consts.PrivateKey:
		params.Metadata[consts.StoreMethod] = cmp.Or(params.Metadata[consts.StoreMethod], consts.DiskStore)
		st, err := params.SwitchStore()
		if err != nil {
			return nil, err
		}
		l = NewPrivateKey(st)
	case consts.AES:
		params.Metadata[consts.StoreMethod] = cmp.Or(params.Metadata[consts.StoreMethod], consts.EnvStore)
		st, err := params.SwitchStore()
		if err != nil {
			return nil, err
		}
		l = NewAes(st)
	default:
		params.Metadata[consts.EncryptionMethod] = cmp.Or(params.Metadata[consts.EncryptionMethod], consts.AES)
		params.Metadata[consts.StoreMethod] = cmp.Or(params.Metadata[consts.StoreMethod], consts.EnvStore)
		st, err := params.SwitchStore()
		if err != nil {
			return nil, err
		}
		l = NewAes(st)
	}

	return l, nil
}

func (l *Aes) GetLicenseContent(name string) (LicenseContent, error) {
	var licenseData LicenseContent
	content, err := l.store.Load(name)
	if err != nil {
		return LicenseContent{}, err
	}

	if len(content) == 0 {
		log.Printf("the content of %s is empty\n", name)
		return LicenseContent{}, nil
	}

	err = json.Unmarshal(content, &licenseData)
	if err != nil {
		return LicenseContent{}, err
	}

	return licenseData, nil
}
