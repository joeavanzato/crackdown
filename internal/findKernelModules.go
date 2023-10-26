package internal

import (
	"fmt"
	"github.com/rs/zerolog"
	"os"
	"os/exec"
	"strings"
	"time"
)

type KernelModule struct {
	Name     string
	Filename string
	Author   string
	Signer   string
	Modified string
	Created  string
}

func FindKernelModules(logger zerolog.Logger, detections chan<- Detection, waitGroup *WaitGroupCount) {
	defer waitGroup.Done()
	logger.Info().Msg("Checking Kernel Modules...")
	cmd := exec.Command("lsmod")
	stdout, err := cmd.Output()
	if err != nil {
		logger.Error().Err(err)
		return
	}
	timestampNow := time.Now()
	lines := strings.Split(string(stdout), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "Module") {
			continue
		}
		lineSplit := strings.Split(l, " ")
		moduleName := strings.TrimSpace(lineSplit[0])
		if moduleName == "" {
			continue
		}
		//fmt.Println(moduleName)
		modcmd := exec.Command("modinfo", moduleName)
		modInfoStdout, err := modcmd.Output()
		if err != nil {
			logger.Error().Err(err)
			continue
		}
		linesMod := strings.Split(string(modInfoStdout), "\n")
		modInfo := KernelModule{
			Name:     "",
			Filename: "",
			Author:   "",
			Signer:   "",
			Modified: "NA",
		}
		for _, ll := range linesMod {
			if strings.HasPrefix(ll, "filename") {
				modInfo.Filename = fmt.Sprintf("%v", strings.TrimSpace(strings.Split(ll, ":")[1]))
			} else if strings.HasPrefix(ll, "signer") {
				modInfo.Signer = strings.TrimSpace(strings.Split(ll, ":")[1])
			} else if strings.HasPrefix(ll, "author") {
				modInfo.Author = strings.TrimSpace(strings.Split(ll, ":")[1])
			} else if strings.HasPrefix(ll, "name") {
				modInfo.Name = strings.TrimSpace(strings.Split(ll, ":")[1])
			}
		}
		fileStat, err := os.Stat(modInfo.Filename)
		if err != nil {
			logger.Error().Err(err)
		} else {
			modInfo.Modified = fileStat.ModTime().UTC().String()
		}
		dayDiff := int(timestampNow.Sub(fileStat.ModTime().UTC()).Hours() / 24)
		if dayDiff <= 30 {
			// Kernel File modified within last 30 days
			tmp_ := map[string]interface{}{
				"ModuleName": modInfo.Name,
				"Filename":   modInfo.Filename,
				"Author":     modInfo.Author,
				"Signer":     modInfo.Signer,
				"Modified":   modInfo.Modified,
				"DaysAgo":    dayDiff,
			}
			detection := Detection{
				Name:      "Kernel Module modified within last 30 days",
				Severity:  3,
				Tip:       "Investigate module to determine validity.",
				Technique: "T1547.006",
				Metadata:  tmp_,
			}
			detections <- detection
		}
	}

}
