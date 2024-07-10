package main

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hu-1996/gosf-license/consts"
	license "github.com/hu-1996/gosf-license/pkg"
	"github.com/hu-1996/gosf-license/pkg/store"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

var (
	output     string
	configPath string
	allPass    bool
	namespace  string
	configmap  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "license",
		Short: "generate and verify software certificate licenses",
		Long:  "generate and verify software certificate licenses",
		CompletionOptions: cobra.CompletionOptions{
			HiddenDefaultCmd: true,
		},
		Run: func(cmd *cobra.Command, args []string) {
			log.Println(args)
		},
	}

	exampleCmd := &cobra.Command{
		Use:   "example",
		Short: "software certificate license example",
		Long:  "software certificate license example",
		Run: func(cmd *cobra.Command, args []string) {
			params := new(license.GenerateParam)
			_, err := chooseEncryptionMethod(params, false)
			if err != nil {
				log.Fatal(err)
			}

			params.Metadata[consts.Namespace] = namespace
			params.Metadata[consts.Configmap] = configmap

			validateK8s := allPass
			if !allPass {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Whether to validate kubernetes resources (Nodes, GPUs)? (yes/no): ")
				response, _ := reader.ReadString('\n')
				response = strings.TrimSpace(strings.ToLower(response))
				validateK8s = response == "yes" || response == "y"
			}

			exparams := &license.ExampleParam{
				LicenseName:    params.LicenseName,
				LicenseSigName: params.LicenseSigName,
				PrivateKeyName: params.PrivateKeyName,
				Metadata:       params.Metadata,
				Extra: map[string]interface{}{
					consts.ValidateNodes: validateK8s,
					consts.ValidateGPUs:  validateK8s,
				},
			}

			if params.Metadata[consts.LicenseType].(string) != consts.Base {
				nodes, _ := license.GetK8sNodes()
				exparams.Extra[consts.Nodes] = nodes

				if params.Metadata[consts.Namespace] == nil {
					params.Metadata[consts.Namespace] = "default"
				}
				if params.Metadata[consts.Configmap] == nil {
					params.Metadata[consts.Configmap] = "cluster-gpu-ids"
				}
				gpus, _ := license.GetGPUs(params.Metadata[consts.Configmap].(string), params.Metadata[consts.Namespace].(string))
				exparams.Extra[consts.GPUs] = gpus
			}

			err = license.Example(exparams)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	exampleCmd.PersistentFlags().BoolVarP(&allPass, "yes", "y", false, "all yes")
	exampleCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "default", "k8s namespace.(if you do not need to acquire GPUs, please ignore.)")
	exampleCmd.PersistentFlags().StringVarP(&configmap, "configmap", "m", "cluster-gpu-ids", "k8s configmap name.(if you do not need to acquire GPUs, please ignore.)")

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "generate software certificate licenses",
		Long:  "generate software certificate licenses",
		Run: func(cmd *cobra.Command, args []string) {
			params := new(license.GenerateParam)
			l, err := chooseEncryptionMethod(params, true)
			if err != nil {
				log.Fatal(err)
			}

			params.Metadata[consts.Overwrite] = allPass
			if !allPass {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Do you want to overwrite the software certificate license? (yes/no): ")
				response, _ := reader.ReadString('\n')
				response = strings.TrimSpace(strings.ToLower(response))
				params.Metadata[consts.Overwrite] = response == "yes" || response == "y"
			}

			err = l.Generate(params)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	generateCmd.PersistentFlags().StringVarP(&output, "output", "o", consts.HomeDir, "output location of the software certificate license")
	generateCmd.PersistentFlags().StringVarP(&configPath, "configPath", "c", "./config.yaml", "license config")
	generateCmd.PersistentFlags().BoolVarP(&allPass, "yes", "y", false, "all yes")

	verifyCmd := &cobra.Command{
		Use:   "validate",
		Short: "validate software certificate licenses",
		Long:  "validate software certificate licenses",
		Run: func(cmd *cobra.Command, args []string) {
			param := license.ValidateParam{
				PrivateAlias:   consts.PrivateAlias,
				KeyPass:        consts.KeyPass,
				StorePass:      consts.StorePass,
				LicenseName:    "/Users/hujialin/.gosf/license",
				LicenseSigName: "/Users/hujialin/.gosf/license.sig",
				PrivateKeyName: "/Users/hujialin/.gosf/privateKeys.keystore",
				NotBefore:      time.Now(),
				NotAfter:       time.Now(),
				Metadata: map[string]interface{}{
					consts.EncryptionMethod: consts.PrivateKey,
					consts.StoreMethod:      consts.DiskStore,
				},
			}

			l, err := param.NewLicense()
			if err != nil {
				log.Fatal(err)
			}

			err = l.LocalValidate(&param)
			if err != nil {
				log.Fatal(err)
			}

			content, err := l.GetLicenseContent(param.LicenseName)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(content)
		},
	}
	verifyCmd.PersistentFlags().StringVarP(&output, "output", "o", consts.HomeDir, "output location of the software certificate license")
	verifyCmd.PersistentFlags().StringVarP(&configPath, "configPath", "c", "./config.yaml", "license config")

	rootCmd.AddCommand(exampleCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(verifyCmd)
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

// chooseEncryptionMethod
func chooseEncryptionMethod(params *license.GenerateParam, readConfig bool) (license.License, error) {
	if params.Metadata == nil {
		params.Metadata = make(map[string]interface{})
	}
	var encryptionType string
	if readConfig {
		err := params.ReadYaml(configPath)
		if err != nil {
			return nil, err
		}

		encryptionType = params.Metadata[consts.EncryptionMethod].(string)
	} else {
		lt, err := switchOption("Please select the license type", []string{consts.Full, consts.Base, consts.Kubernetes})
		if err != nil {
			return nil, err
		}
		params.Metadata[consts.LicenseType] = lt

		et, err := switchOption("Please choose the license encryption method", []string{consts.PrivateKey, consts.AES})
		if err != nil {
			return nil, err
		}
		encryptionType = et
	}

	var l license.License
	switch encryptionType {
	case consts.PrivateKey:
		params.Metadata[consts.EncryptionMethod] = cmp.Or(params.Metadata[consts.EncryptionMethod], consts.PrivateKey)
		params.Metadata[consts.StoreMethod] = cmp.Or(params.Metadata[consts.StoreMethod], consts.DiskStore)
		st, err := switchStore(params)
		if err != nil {
			return nil, err
		}
		l = license.NewPrivateKey(st)
	case consts.AES:
		params.Metadata[consts.EncryptionMethod] = cmp.Or(params.Metadata[consts.EncryptionMethod], consts.AES)
		params.Metadata[consts.StoreMethod] = cmp.Or(params.Metadata[consts.StoreMethod], consts.EnvStore)
		st, err := switchStore(params)
		if err != nil {
			return nil, err
		}
		l = license.NewAes(st)
	default:
		params.Metadata[consts.EncryptionMethod] = cmp.Or(params.Metadata[consts.EncryptionMethod], consts.AES)
		params.Metadata[consts.StoreMethod] = cmp.Or(params.Metadata[consts.StoreMethod], consts.EnvStore)
		st, err := switchStore(params)
		if err != nil {
			return nil, err
		}
		l = license.NewAes(st)
	}

	return l, nil
}

func switchOption(label string, options []string) (string, error) {
	prompt := promptui.Select{
		Label: label,
		Items: options,
	}

	_, result, err := prompt.Run()
	if err != nil {
		return "", err
	}

	return result, nil
}

func switchStore(params *license.GenerateParam) (store.Store, error) {
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
