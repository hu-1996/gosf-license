package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/hu-1996/gosf-license/pkg/server_info"
)

var (
	OsNotSupported     = errors.New("os not supported")
	NotFoundKubeConfig = errors.New("not found env: KUBECONFIG")
)

// GetCPUSerial 仅支持linux
func GetCPUSerial() ([]string, error) {
	switch runtime.GOOS {
	case "linux":
		return server_info.NewLinuxServerInfo().GetCPUSerial()
	}
	return nil, OsNotSupported
}

func GetBaseBoardSerial() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return server_info.NewLinuxServerInfo().GetBaseBoardSerial()
	}
	return "", OsNotSupported
}

func GetIpAddress() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				ip := v.IP.To4()
				if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() {
					ips = append(ips, v.IP.String())
				}
			}
		}
	}

	return ips, nil
}

func GetMacAddress() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var macs []string
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			mac := iface.HardwareAddr.String()
			if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() && mac != "" {
				macs = append(macs, mac)
			}
		}
	}

	return macs, nil
}

func GetK8sNodes() ([]string, error) {
	if os.Getenv("KUBECONFIG") == "" {
		return nil, NotFoundKubeConfig
	}

	fmt.Println("get nodes from k8s")
	command := exec.Command("sh", "-c", "kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{end}'")
	output, err := command.Output()
	if err != nil {
		return nil, err
	}

	nodes := strings.Split(string(output), "\n")
	var ns []string
	for _, node := range nodes {
		if node != "" {
			ns = append(ns, node)
		}
	}
	return ns, nil
}

func GetGPUs(configmap, namespace string) ([]string, error) {
	if os.Getenv("KUBECONFIG") == "" {
		return nil, NotFoundKubeConfig
	}

	fmt.Println("get gpus from k8s configmap")
	command := exec.Command("sh", "-c", fmt.Sprintf("kubectl get configmap %s -o jsonpath='{.data}' -n %s", configmap, namespace))
	output, err := command.Output()
	if err != nil {
		return nil, err
	}

	if len(output) == 0 {
		return nil, errors.New("GPUs is empty")
	}

	//output := `{"gml-dev-04":"GPU-a6e1653b-d968-4c44-e928-b9dc0703bd4a\nGPU-cddb6795-d9da-e00b-9943-e6f224f01e80\nGPU-0ad09cd4-b317-dc2a-1b54-6f634a94057f\nGPU-13ce6205-4357-35d8-a0f9-f23af10a001f\n","gml-dev-07":"GPU-e28d395a-e851-ea9e-84b6-0d582a6e4300\nGPU-492ba06b-15ec-5895-5fa6-605262c500d1\nGPU-670c0de2-7078-4d5c-dcbc-222310e2c258\nGPU-8681ab9e-fbe2-563a-de9a-3c8d3f99e821\n"}`
	var gm map[string]string
	err = json.Unmarshal(output, &gm)
	if err != nil {
		return nil, err
	}

	var gpus []string
	for _, gpusVal := range gm {
		gpuLines := strings.Split(gpusVal, "\n")
		for _, gpu := range gpuLines {
			if gpu != "" {
				gpus = append(gpus, gpu)
			}
		}
	}

	return gpus, nil
}
