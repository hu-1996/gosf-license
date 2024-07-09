package consts

const (
	HomeDir   = "${user.home}/.gosf"
	WorkSpace = ".gosf"
	Subject   = "gosf_license"
	KeyPass   = "keypass@12345678" // 16位，否则aes会报错

	PrivateAlias   = "privateKey"
	StorePass      = "storepass@123456"
	LicenseName    = "license"
	LicenseSigName = "license.sig"
	PrivateKeys    = "privateKeys.keystore"

	LicenseEnv    = "GOSF_LICENSE"
	LicenseSigEnv = "GOSF_LICENSE_SIG"

	ConsumerType       = "gosf"
	ConsumerAmount int = 1
	Description        = "产品授权许可证书"
)

const (
	PrivateKey = "privateKey"
	AES        = "aes"
)

const (
	DiskStore = "disk store"
	EnvStore  = "env store"
)

const (
	ValidateNodes = "validateNodes"
	ValidateGPUs  = "validateGPUs"
	Nodes         = "nodes"
	GPUs          = "GPUs"
)
