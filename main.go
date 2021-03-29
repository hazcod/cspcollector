package main

import (
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

var (
	// Shared defaults for the logger output. This ensures that we are
	// using the same keys for the `FieldKey` values across both formatters.
	logFieldMapDefaults = log.FieldMap{
		log.FieldKeyTime:  "timestamp",
		log.FieldKeyLevel: "level",
		log.FieldKeyMsg:   "message",
	}

	// Default URI Filter list
	ignoredBlockedURIs = []string{
		"resource://",
		"chromenull://",
		"chrome-extension://",
		"safari-extension://",
		"mxjscall://",
		"webviewprogressproxy://",
		"res://",
		"mx://",
		"safari-resource://",
		"chromeinvoke://",
		"chromeinvokeimmediate://",
		"mbinit://",
		"opera://",
		"ms-appx://",
		"ms-appx-web://",
		"localhost",
		"127.0.0.1",
		"none://",
		"about:blank",
		"android-webview",
		"ms-browser-extension",
		"wvjbscheme://__wvjb_queue_message__",
		"nativebaiduhd://adblock",
		"bdvideo://error",
	}
)

func main() {
	var logLevel, dbFilepath, healthCheckPath, listenHost, listenURI, hostWhitelist string

	var listenPort int

	flag.StringVar(&logLevel, "loglevel", "debug", "Output additional logging for debugging")
	flag.StringVar(&listenURI, "uri", "/", "HTTP path to listen on")
	flag.StringVar(&listenHost, "host", "127.0.0.1", "Host to listen on")
	flag.StringVar(&hostWhitelist, "whitelist", "", "A comma-separated list of whitelisted top domains")
	flag.IntVar(&listenPort, "port", 8080, "Port to listen on")
	flag.StringVar(&healthCheckPath, "health-check-path", "/_healthcheck", "Health checker path")
	flag.StringVar(&dbFilepath, "db", "csp.db", "Filepath to the sqlite database")

	flag.Parse()

	if logLevel, err := log.ParseLevel(logLevel); err != nil {
		log.WithError(err).Error("could not set log level")
		log.SetLevel(log.InfoLevel)
	} else {
		log.WithField("log_level", logLevel.String()).Debug("set log level")
		log.SetLevel(logLevel)
	}

	log.SetFormatter(&log.JSONFormatter{
		FieldMap: logFieldMapDefaults,
	})

	whitelist := []string{}
	for _, item := range strings.Split(hostWhitelist, ",") {
		whitelist = append(whitelist, strings.ToLower(strings.TrimSpace(item)))
	}

	log.WithField("db", dbFilepath).Debug("opening database")

	dbStorage, err := OpenSqlite3Database(dbFilepath)
	if err != nil {
		log.WithError(err).Fatal("could not open database")
	}

	defer func() {
		if err := dbStorage.Close(); err != nil {
			log.WithError(err).Warn("error during db closure")
		}

		log.Debug("closed connection to database")
	}()

	log.Debug("initializing database")

	if err := dbStorage.InitializeDatabase(); err != nil {
		log.WithError(err).Fatal("could not migrate database")
	}

	log.Debugf("Listening on TCP %s:%s", listenHost, strconv.Itoa(listenPort))

	http.HandleFunc(listenURI, gethandleViolationReportHandler(dbStorage, healthCheckPath, whitelist))

	if err := http.ListenAndServe(fmt.Sprintf("%s:%s", listenHost, strconv.Itoa(listenPort)), nil); err != nil {
		log.WithError(err).Error("cannot run listener")
	}
}
