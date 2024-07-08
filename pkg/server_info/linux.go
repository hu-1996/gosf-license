package server_info

import (
	"os"
	"os/exec"
	"strings"
)

var _ ServerInfo = (*LinuxServerInfo)(nil)

type LinuxServerInfo struct {
}

func NewLinuxServerInfo() *LinuxServerInfo {
	return new(LinuxServerInfo)
}

func (s *LinuxServerInfo) GetCPUSerial() ([]string, error) {
	content, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil, err
	}

	cpus := make(map[string]struct{})
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "model name") {
			cpus[strings.TrimSpace(strings.Split(line, ":")[1])] = struct{}{}
		}
	}

	serial := make([]string, 0, len(cpus))
	for modelName := range cpus {
		serial = append(serial, modelName)
	}

	return serial, nil
}

func (s *LinuxServerInfo) GetMainBoardSerial() (string, error) {
	command := exec.Command("sh", "-c", "dmidecode | grep 'Serial Number' | awk '{print $3}' | tail -1")
	output, err := command.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}
