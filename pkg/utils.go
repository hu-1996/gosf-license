package license

import (
	"errors"
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

func GetMainBoardSerial() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return server_info.NewLinuxServerInfo().GetMainBoardSerial()
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
