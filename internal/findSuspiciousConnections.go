package internal

import (
	"github.com/bastjan/netstat"
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/rs/zerolog"
	"net"
	"strconv"
	"strings"
)

var suspiciousPorts = map[int]bool{
	20:   true,
	21:   true,
	22:   true,
	23:   true,
	25:   true,
	53:   true,
	137:  true,
	139:  true,
	445:  true,
	3389: true,
}

func FindSuspiciousConnections(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	// TODO - Suspicious Ports
	// TODO - Suspicious Executable with Network Connection
	logger.Info().Msg("Finding Suspicious Connections...")
	connections, err := netstat.TCP.Connections()
	if err != nil {
		logger.Error().Err(err)
		return
	}
	skipIPs := map[string]bool{
		"0.0.0.0":   true,
		"127.0.0.1": true,
	}
	suspiciousExeLocations := []string{
		"/home/games",
		"/home/lib",
		"/home/local",
		"/home/sbin",
		"/home/share",
		"/home/src",
		"/usr/",
	}
	appAllowList := []string{
		"usr/lib/firefox/firefox",
	}
	tenDot := net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	sevenTwoDot := net.IPNet{
		IP:   net.ParseIP("172.16.0.0"),
		Mask: net.CIDRMask(12, 32),
	}
	oneNineTwoDot := net.IPNet{
		IP:   net.ParseIP("192.168.0.0"),
		Mask: net.CIDRMask(16, 32),
	}

	for _, v := range connections {
		if skipIPs[v.RemoteIP.String()] {
			continue
		}
		// Skip private-network connections
		if tenDot.Contains(v.RemoteIP) || sevenTwoDot.Contains(v.RemoteIP) || oneNineTwoDot.Contains(v.RemoteIP) {
			continue
		}
		tmp_ := map[string]interface{}{
			"RemoteAddress": v.RemoteIP.String(),
			"LocalPort":     strconv.Itoa(v.Port),
			"RemotePort":    strconv.Itoa(v.RemotePort),
			"Executable":    v.Exe,
			"Commandline":   strings.Join(v.Cmdline, " "),
		}
		detection := Detection{
			Name:      "Executable in Home Directory with Network Connection",
			Severity:  2,
			Tip:       "Investigate connection to determine validity.",
			Technique: "T1071",
			Metadata:  tmp_,
		}
		allowMatch := false
	allowPattern:
		for _, loc := range appAllowList {
			if helpers.SearchStringContains(v.Exe, loc) {
				allowMatch = true
				break allowPattern
			}
		}
		if allowMatch {
			continue
		}

		if suspiciousPorts[v.Port] {
			detection.Name = "Connection on Suspicious Port"
			detections <- detection
			continue
		}
	patternMatch:
		for _, loc := range suspiciousExeLocations {
			if helpers.SearchStringContains(v.Exe, loc) {
				detection.Name = "Executable in abnormal directory with network connection"
				detection.Metadata["Pattern"] = loc
				detections <- detection
				break patternMatch
			}
		}
		//logger.Info(v)
	}
	return
}
