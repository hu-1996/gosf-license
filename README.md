### gosf-license

一个生成软件许可证书的库

A library for generating software license certificates.

`go get -u github.com/hu-1996/gosf-license`

### 使用方法 useage
#### build

`GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ./bin/license`

#### 生成配置文件，会自动读取当前机器的ip，mac address和主板到配置文件

Generate a configuration file, which will automatically read the current machine's IP, MAC address, and main board into the configuration file.

```shell
$ license example
```

当前目录下会生成config.yaml文件，如有需要，请自行修改里边的内容

A config.yaml file will be generated in the current directory. Please feel free to modify its contents as needed.

#### 生成证书许可 Generate certificate license

- 使用cmd生成证书，如果需要指定证书输出位置，请携带 -o 参数 
- To generate a certificate using cmd, if you need to specify the certificate output location, please use the -o parameter.
```shell
$ license generate -c ./config.yaml
```
- 调用函数生成证书 
- Call the function to generate the certificate.
```go
license.Generate(params)
```
#### 验证证书许可证 Validate certificate license
- 使用cmd验证，只能验证基础信息：ip，mac address和主板
- Use cmd to validate; it can only validate basic information: such as IP, MAC address, and main board.
```shell
$ license validate -c ./config.yaml
```
- 调用函数验证，LocalValidate会自动在param参数中补全基础信息：ip，mac address和主板，Validate请自主填写ip，mac address和主板信息，如果生成的证书包含Extra，验证它时，请设置ExtraValidateFunc参数进行自定义验证
- Function call verification: LocalValidate automatically completes basic information in the param parameter: IP, MAC address, and motherboard. For Validate, please fill in the IP, MAC address, and motherboard information independently. If the generated certificate includes Extra, when verifying it, please set the ExtraValidateFunc parameter for custom verification.
```go
license.LocalValidate(&param)
license.Validate(&param)
```