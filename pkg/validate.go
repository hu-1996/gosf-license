package license

import (
	"cmp"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"

	"github.com/hu-1996/gosf-license/consts"
)

type ValidateParam struct {
	PrivateAlias         string                 // 密钥别称
	KeyPass              string                 // 密钥密码（需要妥善保管，不能让使用者知道）
	StorePass            string                 // 访问秘钥库的密码
	LicensePath          string                 // 证书生成路径
	PrivateKeysStorePath string                 // 密钥库存储路径
	LicenseCheckModel    *CheckModel            `json:"licenseCheckModel"` // 服务器硬件校验信息
	Extra                map[string]interface{} `json:"extra"`             // 额外的校验信息
	ExtraValidateFunc    func(licenseExtra, validateExtra map[string]interface{}) error
}

// LocalValidate 验证软件证书许可，会自动补全本机的CPU，IP，MAC address并与License进行验证
func LocalValidate(param *ValidateParam) error {
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

	err := Validate(param)
	if err != nil {
		return err
	}

	return nil
}

// Validate 验证软件证书许可，不会自动补全本机的CPU，IP，MAC address，请自行补充信息
func Validate(param *ValidateParam) error {
	err := param.prepareVerifyParam()
	if err != nil {
		return err
	}

	_, cert, err := loadKeyStore(param.PrivateKeysStorePath, param.StorePass, param.PrivateAlias, param.KeyPass)
	if err != nil {
		return err
	}

	// 验证许可证
	err = validateLicense(param.LicensePath, cert)
	if err != nil {
		return err
	}

	// 验证cpu
	licenseData := new(GenerateParam)
	err = licenseData.ReadYaml(filepath.Join(param.LicensePath, consts.LicenseFile))
	if err != nil {
		return err
	}

	// 验证cpu
	if len(param.LicenseCheckModel.CpuSerial) > 0 {
		for _, cpu := range param.LicenseCheckModel.CpuSerial {
			if !slices.Contains(licenseData.LicenseCheckModel.CpuSerial, cpu) {
				return fmt.Errorf("cpu[%s] unauthorized", cpu)
			}
		}
	}

	// 验证主板
	if param.LicenseCheckModel.MainBoardSerial != "" && param.LicenseCheckModel.MainBoardSerial != licenseData.LicenseCheckModel.MainBoardSerial {
		return fmt.Errorf("main board[%s] unauthorized", param.LicenseCheckModel.MainBoardSerial)
	}

	// 验证ipAddress
	for _, ip := range param.LicenseCheckModel.IpAddress {
		if !slices.Contains(licenseData.LicenseCheckModel.IpAddress, ip) {
			return fmt.Errorf("ip[%s] unauthorized", ip)
		}
	}

	// 验证macAddress
	for _, macAddr := range param.LicenseCheckModel.MacAddress {
		if !slices.Contains(licenseData.LicenseCheckModel.MacAddress, macAddr) {
			return fmt.Errorf("mac address[%s] unauthorized", macAddr)
		}
	}

	// 验证extra
	if param.ExtraValidateFunc != nil {
		err := param.ExtraValidateFunc(licenseData.Extra, param.Extra)
		if err != nil {
			return err
		}
	}

	fmt.Println("pkg valid！")
	return nil
}

func (p *ValidateParam) prepareVerifyParam() error {
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
	return nil
}

func validateLicense(licensePath string, cert *x509.Certificate) error {
	licenseFileData, err := os.ReadFile(filepath.Join(licensePath, consts.LicenseFile))
	if err != nil {
		return err
	}

	licenseSigFileData, err := os.ReadFile(filepath.Join(licensePath, consts.LicenseSigFile))
	if err != nil {
		return err
	}

	hash := sha256.New()
	_, err = hash.Write(licenseFileData)
	if err != nil {
		return fmt.Errorf("failed to hash pkg data: %v", err)
	}

	err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash.Sum(nil), licenseSigFileData)
	if err != nil {
		return fmt.Errorf("failed to validate pkg: %v", err)
	}

	return nil
}
