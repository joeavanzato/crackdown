package internal

import (
	"fmt"
	"github.com/javanzato/crackdown/internal/helpers"
	"github.com/mitchellh/go-ps"
	"github.com/sirupsen/logrus"
	"strconv"
)

func FindSuspiciousCommandlines(logger *logrus.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info("Finding Suspicious Processes...")
	processList, err := ps.Processes()
	if err != nil {
		logger.Error("Failed to get Running Process list!")
		return
	}
	// https://detection.fyi/sigmahq/sigma/linux/builtin/lnx_shell_susp_rev_shells/
	suspiciousPatterns := []string{
		"BEGIN {s = \"/inet/tcp/0/",
		"bash -i >& /dev/tcp/",
		"bash -i >& /dev/udp/",
		"sh -i >$ /dev/udp/",
		"sh -i >$ /dev/tcp/",
		"&& while read line 0<&5; do",
		"/bin/bash -c exec 5<>/dev/tcp/",
		"/bin/bash -c exec 5<>/dev/udp/",
		"nc -e /bin/sh ",
		"/bin/sh | nc",
		"rm -f backpipe; mknod /tmp/backpipe p && nc ",
		";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i))))",
		";STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;",
		"/bin/sh -i <&3 >&3 2>&3",
		"uname -a; w; id; /bin/bash -i",
		"([text.encoding]::ASCII).GetBytes",
		"$stream.Flush()",
		"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)",
		"while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print",
		"socat exec:''bash -li'',pty,stderr,setsid,sigint,sane tcp",
		"rm -f /tmp/p; mknod /tmp/p p &&",
		"/bin/bash | telnet",
		"echo=0,raw tcp-listen:",
		"nc -lvvp",
		"xterm -display 1",
	}
	// TODO - Suspicious Executable Locations

	for x := range processList {
		var process ps.Process
		process = processList[x]
		cmdlineLocation := fmt.Sprintf("/proc/%d/cmdline", process.Pid())
		cmdline := helpers.ReadFileToString(cmdlineLocation, logger)
		fullCommandLine := fmt.Sprintf("%s %s", process.Executable(), cmdline)
	patternMatch:
		for _, pattern := range suspiciousPatterns {
			//logger.Info(pattern)
			if helpers.SearchStringContains(fullCommandLine, pattern) {
				tmp_ := map[string]string{
					"Commandline": fullCommandLine,
					"Pattern":     pattern,
					"PID":         strconv.Itoa(process.Pid()),
				}
				detection := Detection{
					Name:      "Suspicious Commandline",
					Severity:  2,
					Tip:       "Investigate process to determine validity.",
					Technique: "T1059",
					Metadata:  tmp_,
				}
				detections <- detection
				break patternMatch
			}
		}
		//logger.Printf("PID: %d, CMDLINE: %s", process.Pid(), fullCommandLine)
	}
	return
}
