package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/hu-1996/gosf-license/consts"
	license "github.com/hu-1996/gosf-license/pkg"
	"github.com/spf13/cobra"
)

var (
	output     string
	configPath string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "pkg",
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
		Short: "software certificate pkg example",
		Long:  "software certificate pkg example",
		Run: func(cmd *cobra.Command, args []string) {
			err := license.Example()
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "generate software certificate licenses",
		Long:  "generate software certificate licenses",
		Run: func(cmd *cobra.Command, args []string) {
			params := new(license.GenerateParam)
			err := params.ReadYaml(configPath)
			if err != nil {
				log.Fatal(err)
			}

			if output == consts.HomeDir || params.LicensePath == "" || params.LicensePath == consts.HomeDir {
				home, err := os.UserHomeDir()
				if err != nil {
					log.Fatal(err)
				}
				params.LicensePath = filepath.Join(home, consts.WorkSpace)
			}

			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Do you want to overwrite the software certificate pkg? (yes/no): ")
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			params.Overwrite = response == "yes" || response == "y"

			err = license.Generate(params)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	generateCmd.PersistentFlags().StringVarP(&output, "output", "o", consts.HomeDir, "output location of the software certificate pkg")
	generateCmd.PersistentFlags().StringVarP(&configPath, "configPath", "c", "./config.yaml", "pkg config")

	verifyCmd := &cobra.Command{
		Use:   "validate",
		Short: "validate software certificate licenses",
		Long:  "validate software certificate licenses",
		Run: func(cmd *cobra.Command, args []string) {
			config, err := readConfig()
			if err != nil {
				log.Fatal(err)
			}

			param := license.ValidateParam{
				PrivateAlias:         config.PrivateAlias,
				KeyPass:              config.KeyPass,
				StorePass:            config.StorePass,
				LicensePath:          config.LicensePath,
				PrivateKeysStorePath: config.PrivateKeysStorePath,
				//LicenseCheckModel: pkg.CheckModel{
				//	MainBoardSerial: "abc",
				//},
				//Extra: map[string]interface{}{
				//	"nodes": "aaa",
				//},
				//ExtraValidateFunc: func(licenseExtra, validateExtra map[string]interface{}) error {
				//	if licenseExtra == nil {
				//		return nil
				//	}
				//
				//	for key, val := range validateExtra {
				//		if v, ok := licenseExtra[key]; ok && v != val {
				//			return fmt.Errorf("%s[%s] unauthorized", key, val)
				//		}
				//	}
				//
				//	return nil
				//},
			}
			err = license.LocalValidate(&param)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	verifyCmd.PersistentFlags().StringVarP(&output, "output", "o", consts.HomeDir, "output location of the software certificate pkg")
	verifyCmd.PersistentFlags().StringVarP(&configPath, "configPath", "c", "./config.yaml", "pkg config")

	rootCmd.AddCommand(exampleCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(verifyCmd)
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

func readConfig() (*license.GenerateParam, error) {
	params := new(license.GenerateParam)
	err := params.ReadYaml(configPath)
	if err != nil {
		return nil, err
	}

	if output == consts.HomeDir || params.LicensePath == "" || params.LicensePath == consts.HomeDir {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		params.LicensePath = filepath.Join(home, consts.WorkSpace)
	}

	return params, nil
}
