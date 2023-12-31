package main

// TODO - Startup Files ~/.config/autostart/
// https://arcolinux.com/how-to-autostart-any-application-on-any-linux-desktop/
// TODO - Driver checks - covered by kernel checks?
// TODO - apt.conf.d directory for recent files/suspicious patterns
// TODO - Check ~/.gitconfig for suspicious patterns/modifications
// TODO - Check .git/hooks for suspicious patterns/recent files
// TODO - Inspect SUDOers file for NOPASSWD Entries
// https://research.splunk.com/endpoint/ab1e0d52-624a-11ec-8e0b-acde48001122/
// https://askubuntu.com/questions/334318/sudoers-file-enable-nopasswd-for-user-all-commands
// TODO - Find better way to abstract generic content checking for suspicious-ness - to much re-use of same logic

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/javanzato/crackdown/internal"
	"github.com/rs/zerolog"
	"io"
	"os"
	"strings"
	"time"
)

const logFile = "crackdown.log"

var severityMap = map[int]string{
	0: "INFO",
	1: "LOW",
	2: "MEDIUM",
	3: "HIGH",
	4: "CRITICAL",
}

type anyMap map[string]interface{}

func setupLogger() zerolog.Logger {
	logFileName := logFile
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		_, err := fmt.Fprintf(os.Stderr, "Couldn't Initialize Log File: %s", err)
		if err != nil {
			panic(nil)
		}
		panic(err)
	}
	cw := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
		FormatLevel: func(i interface{}) string {
			return strings.ToUpper(fmt.Sprintf("[%s]", i))
		},
	}
	mw := io.MultiWriter(cw, logFile)
	logger := zerolog.New(mw).Level(zerolog.TraceLevel)
	logger = logger.With().Timestamp().Logger()
	return logger
}

func printLogo() {
	fmt.Println(`	                        __       __                  `)
	fmt.Println(`	  ______________ ______/ /______/ /___ _      ______ `)
	fmt.Println("	 / ___/ ___/ __ '/ ___/ //_/ __  / __ \\ | /| / / __ \\")
	fmt.Println(`	/ /__/ /  / /_/ / /__/ ,< / /_/ / /_/ / |/ |/ / / / /`)
	fmt.Println(`	\___/_/   \__,_/\___/_/|_|\__,_/\____/|__/|__/_/ /_/ `)
	fmt.Println("	crackdown: Linux Persistence Hunting")
	fmt.Println("	github.com/joeavanzato/crackdown")
}

func listenDetections(logger zerolog.Logger, c chan internal.Detection) ([]internal.Detection, int) {
	detectionCount := 0
	total := 0
	detections := make([]internal.Detection, 20)
detectionListen:
	for {
		detection, ok := <-c
		if !ok {
			break detectionListen
		} else {
			detections = append(detections, detection)
			detectionCount += 1
			total += 1
		}
		if total%20 == 0 {
			total = 0
			curMsg := fmt.Sprintf("Waiting for Detections: %v", detectionCount)
			logger.Info().Msg(curMsg)
		}
	}
	return detections, detectionCount
}

func closeChannelWhenDone(c chan internal.Detection, waitGroup *internal.WaitGroupCount) {
	waitGroup.Wait()
	close(c)
}

func parseArgs(logger zerolog.Logger) anyMap {
	quiet := flag.Bool("quiet", false, "Suppress most Console Logging")

	flag.Parse()
	arguments := anyMap{
		"quiet": *quiet,
	}
	return arguments
}

func writeJSONOut(logger zerolog.Logger, detections []internal.Detection, detectionCount int) {
	detections = detections[len(detections)-detectionCount:]
	content, err := json.MarshalIndent(detections, "", "\t")
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	f, err := os.Create("detections.json")
	if err != nil {
		panic(err)
	}
	_, err = f.Write(content)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
}

func writeCSVOut(logger zerolog.Logger, detections []internal.Detection, detectionCount int) {
	detections = detections[len(detections)-detectionCount:]
	f, err := os.Create("detections.csv")
	if err != nil {
		panic(err)
	}
	headers := []string{
		"Name",
		"Severity",
		"Tip",
		"Technique",
		"Metadata",
	}
	w := csv.NewWriter(f)
	err = w.Write(headers)
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	for i := 0; i < detectionCount; i++ {
		v := detections[i]
		strSlice := []string{
			v.Name,
			severityMap[v.Severity],
			v.Tip,
			v.Technique,
			v.MetaToJSON(),
			//v.MetaToPairs("|||"),
		}
		//fmt.Println(i)
		//fmt.Println(strSlice)
		err := w.Write(strSlice)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func main() {
	logger := setupLogger()
	arguments := parseArgs(logger)
	printLogo()
	//  Channel Initial Allocation necessary?
	receiveDetections := make(chan internal.Detection)
	var waitGroup internal.WaitGroupCount
	waitGroup.Add(12)
	go internal.FindLocalUsers(logger, receiveDetections, &waitGroup)
	go internal.FindCronJobs(logger, receiveDetections, &waitGroup)
	go internal.FindSuspiciousCommandlines(logger, receiveDetections, &waitGroup)
	go internal.FindSuspiciousConnections(logger, receiveDetections, &waitGroup)
	go internal.FindSSHAuthorizedKeys(logger, receiveDetections, &waitGroup)
	go internal.FindKernelModules(logger, receiveDetections, &waitGroup)
	go internal.CheckShellConfigs(logger, receiveDetections, &waitGroup)
	go internal.CheckStartupServices(logger, receiveDetections, &waitGroup)
	go internal.CheckUserStartupScripts(logger, receiveDetections, &waitGroup)
	go internal.CheckCommonBackdoors(logger, receiveDetections, &waitGroup)
	go internal.CheckEnvironmentVariables(logger, receiveDetections, &waitGroup)
	go internal.FindWebShells(logger, receiveDetections, &waitGroup)
	go closeChannelWhenDone(receiveDetections, &waitGroup)
	detections, detectionCount := listenDetections(logger, receiveDetections)
	logger.Info().Msgf("Detection Count: %d", detectionCount)
	if arguments["quiet"] == false {
		for _, i := range detections {
			if i.Metadata != nil {
				// The slice might be longer than the 'real' elements present.
				logger.Info().
					Str(" Name", i.Name).
					Str(" Severity", severityMap[i.Severity]).
					Str("Tip", i.Tip).
					Fields(i.Metadata).Msg("")
			}
		}
	}
	writeJSONOut(logger, detections, detectionCount)
	writeCSVOut(logger, detections, detectionCount)
}
