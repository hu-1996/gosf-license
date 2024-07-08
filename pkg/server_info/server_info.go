package server_info

type ServerInfo interface {
	GetCPUSerial() ([]string, error)
	GetMainBoardSerial() (string, error)
}
