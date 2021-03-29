package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func gethandleViolationReportHandler(storage DatabaseStorage, healthCheckPath string, whitelist []string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == healthCheckPath {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			log.WithFields(log.Fields{
				"http_method": r.Method,
			}).Debug("Received invalid HTTP method")
			return
		}

		decoder := json.NewDecoder(r.Body)
		var report CSPReport

		if err := decoder.Decode(&report); err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			log.Debug(fmt.Sprintf("Unable to decode invalid JSON payload: %s", err))
			return
		}
		defer r.Body.Close()

		reportValidation := validateViolation(report, whitelist)
		if reportValidation != nil {
			http.Error(w, reportValidation.Error(), http.StatusBadRequest)
			log.Debug(fmt.Sprintf("Received invalid payload: %s", reportValidation.Error()))
			return
		}

		metadatas, gotMetadata := r.URL.Query()["metadata"]
		var metadata string
		if gotMetadata {
			metadata = metadatas[0]
		}

		log.WithFields(log.Fields{
			"document_uri":        report.Body.DocumentURI,
			"referrer":            report.Body.Referrer,
			"blocked_uri":         report.Body.BlockedURI,
			"violated_directive":  report.Body.ViolatedDirective,
			"effective_directive": report.Body.EffectiveDirective,
			"original_policy":     report.Body.OriginalPolicy,
			"disposition":         report.Body.Disposition,
			"script_sample":       report.Body.ScriptSample,
			"status_code":         report.Body.StatusCode,
			"metadata":            metadata,
		}).Debug()

		if err := storage.Store(&report.Body); err != nil {
			log.WithError(err).Warn("could not store CSP violation")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.WithField("blocked_uri", report.Body.BlockedURI).Info("stored CSP violation")
		w.WriteHeader(http.StatusOK)
	}
}
