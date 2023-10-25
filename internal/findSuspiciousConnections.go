package internal

import (
	"github.com/bastjan/netstat"
	"github.com/sirupsen/logrus"
)

var suspiciousPorts = map[int]string{
	20:   "UDP",
	21:   "FTP",
	22:   "SSH",
	23:   "TELNET",
	25:   "SMTP",
	53:   "DNS",
	137:  "NETBIOS",
	139:  "SMB",
	445:  "SMB",
	3389: "RDP",
}

func FindSuspiciousConnections(logger *logrus.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	// TODO - Suspicious Ports
	// TODO - Suspicious Executable with Network Connection
	logger.Info("Finding Suspicious Connections...")
	connections, err := netstat.TCP.Connections()
	if err != nil {
		logger.Error(err)
		return
	}
	for _, v := range connections {
		if string(v.RemoteIP) == "0.0.0.0" {
			continue
		}
		//logger.Info(v)
	}
	return
}
