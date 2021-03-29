package main

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

// CSPReport is the structure of the HTTP payload the system receives.
type CSPReport struct {
	Body CSPReportBody `json:"csp-report"`
}

// CSPReportBody contains the fields that are nested within the
// violation report.
type CSPReportBody struct {
	DocumentURI        string      `json:"document-uri"`
	Referrer           string      `json:"referrer"`
	BlockedURI         string      `json:"blocked-uri"`
	ViolatedDirective  string      `json:"violated-directive"`
	EffectiveDirective string      `json:"effective-directive"`
	OriginalPolicy     string      `json:"original-policy"`
	Disposition        string      `json:"disposition"`
	ScriptSample       string      `json:"script-sample"`
	StatusCode         interface{} `json:"status-code"`
}

func validateViolation(r CSPReport, whitelist []string) error {
	for _, value := range ignoredBlockedURIs {
		if strings.HasPrefix(r.Body.BlockedURI, value) {
			return errors.New("blocked URI is an invalid resource: " + r.Body.BlockedURI)
		}
	}

	if !strings.HasPrefix(r.Body.DocumentURI, "http") {
		return fmt.Errorf("document URI ('%s') is invalid", r.Body.DocumentURI)
	}

	if len(whitelist) == 0 || r.Body.DocumentURI == "" {
		return nil
	}

	hostName := strings.ToLower(r.Body.DocumentURI)
	for _, item := range whitelist {
		if strings.Contains(hostName, item) {
			return nil
		}
	}

	return errors.New("non-whietlisted domain detected")
}
