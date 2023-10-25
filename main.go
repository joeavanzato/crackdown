package main

import (
	"fmt"
	"github.com/javanzato/crackdown/internal"
	"github.com/sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
	"io"
	"os"
)

func setupLogger() *logrus.Logger {
	logFileName := "crackdown.log"
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		_, err := fmt.Fprintf(os.Stderr, "Couldn't Initialize Log File: %s", err)
		if err != nil {
			panic(nil)
		}
		panic(err)
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	logger := &logrus.Logger{
		Out:   mw,
		Level: logrus.DebugLevel,
		Formatter: &prefixed.TextFormatter{
			DisableColors:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			FullTimestamp:   true,
			ForceFormatting: true,
		},
	}
	fmt.Println(`                        __       __                  `)
	fmt.Println(`  ______________ ______/ /______/ /___ _      ______ `)
	fmt.Println(" / ___/ ___/ __ '/ ___/ //_/ __  / __ \\ | /| / / __ \\")
	fmt.Println(`/ /__/ /  / /_/ / /__/ ,< / /_/ / /_/ / |/ |/ / / / /`)
	fmt.Println(`\___/_/   \__,_/\___/_/|_|\__,_/\____/|__/|__/_/ /_/ `)
	logger.Info("crackdown: Linux Persistence Hunting")
	logger.Debug("github.com/joeavanzato/crackdown")
	return logger
}

func main() {
	logger := setupLogger()
	severity_map := map[int]string{
		0: "INFO",
		1: "LOW",
		2: "MEDIUM",
		3: "HIGH",
		4: "CRITICAL",
	}
	logger.Info(severity_map)
	detections := make([]internal.Detection, 20)
	detections = internal.FindLocalUsers(logger, detections)
	detections = internal.FindCronJobs(logger, detections)
	detections = internal.FindSuspiciousCommandlines(logger, detections)
	/*for _, v := range detections {
		fmt.Println(v)
	}*/
}
