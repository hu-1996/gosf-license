package main

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"github.com/hu-1996/gosf-license/consts"
	license "github.com/hu-1996/gosf-license/pkg"
	"github.com/hu-1996/gosf-license/pkg/store"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	output     string
	configPath string
	allPass    bool
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

			validateK8s := allPass
			if !allPass {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Whether to validate kubernetes resources (Nodes, GPUs)? (yes/no): ")
				response, _ := reader.ReadString('\n')
				response = strings.TrimSpace(strings.ToLower(response))
				validateK8s = response == "yes" || response == "y"
			}
			nodes, _ := license.GetK8sNodes()
			exparams := &license.ExampleParam{
				EncryptionMethod:     params.EncryptionMethod,
				StoreMethod:          params.StoreMethod,
				LicenseName:          params.LicenseName,
				LicenseSigName:       params.LicenseSigName,
				PrivateKeysStoreName: params.PrivateKeysStoreName,
				Extra: map[string]interface{}{
					consts.ValidateNodes: validateK8s,
					consts.ValidateGPUs:  validateK8s,
					consts.Nodes:         nodes,
				},
			}

			err = license.Example(exparams)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	exampleCmd.PersistentFlags().BoolVarP(&allPass, "yes", "y", false, "all yes")

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

			params.Overwrite = allPass
			if !allPass {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Do you want to overwrite the software certificate license? (yes/no): ")
				response, _ := reader.ReadString('\n')
				response = strings.TrimSpace(strings.ToLower(response))
				params.Overwrite = response == "yes" || response == "y"
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
			params := new(license.GenerateParam)
			l, err := chooseEncryptionMethod(params, true)
			if err != nil {
				log.Fatal(err)
			}

			param := license.ValidateParam{
				EncryptionMethod:     params.EncryptionMethod,
				StoreMethod:          params.StoreMethod,
				PrivateAlias:         params.PrivateAlias,
				KeyPass:              params.KeyPass,
				StorePass:            params.StorePass,
				LicenseName:          params.LicenseName,
				LicenseSigName:       params.LicenseSigName,
				PrivateKeysStoreName: params.PrivateKeysStoreName,
				NotBefore:            time.Now(),
				NotAfter:             time.Now(),
			}
			err = l.LocalValidate(&param)
			if err != nil {
				log.Fatal(err)
			}
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

// chooseEncryptionMethod 只在example时使用
func chooseEncryptionMethod(params *license.GenerateParam, readConfig bool) (license.License, error) {
	var encryptionType string
	if readConfig {
		err := params.ReadYaml(configPath)
		if err != nil {
			return nil, err
		}

		encryptionType = params.EncryptionMethod
	} else {
		options := []string{consts.PrivateKey, consts.AES}

		prompt := promptui.Select{
			Label: "Please choose the license encryption method",
			Items: options,
		}

		_, result, err := prompt.Run()
		if err != nil {
			return nil, err
		}

		encryptionType = result
	}

	var l license.License
	switch encryptionType {
	case consts.PrivateKey:
		params.EncryptionMethod = cmp.Or(params.EncryptionMethod, consts.PrivateKey)
		params.StoreMethod = cmp.Or(params.StoreMethod, consts.DiskStore)
		st, err := switchStore(params)
		if err != nil {
			return nil, err
		}
		l = license.NewPrivateKey(st)
	case consts.AES:
		params.EncryptionMethod = cmp.Or(params.EncryptionMethod, consts.AES)
		params.StoreMethod = cmp.Or(params.StoreMethod, consts.EnvStore)
		st, err := switchStore(params)
		if err != nil {
			return nil, err
		}
		l = license.NewAes(st)
	default:
		params.EncryptionMethod = cmp.Or(params.EncryptionMethod, consts.AES)
		params.StoreMethod = cmp.Or(params.StoreMethod, consts.EnvStore)
		st, err := switchStore(params)
		if err != nil {
			return nil, err
		}
		l = license.NewAes(st)
	}

	return l, nil
}

func switchStore(params *license.GenerateParam) (store.Store, error) {
	switch params.StoreMethod {
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

		if params.PrivateKeysStoreName == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			params.PrivateKeysStoreName = filepath.Join(home, consts.WorkSpace, consts.PrivateKeys)
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
