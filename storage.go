package main

import (
	"database/sql"
	"net/url"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
)

type DatabaseStorage struct {
	db *sql.DB
}

func OpenSqlite3Database(dsn string) (DatabaseStorage, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return DatabaseStorage{}, errors.Wrap(err, "could not open database")
	}

	return DatabaseStorage{db: db}, nil
}

func (s *DatabaseStorage) Close() error {
	if s.db == nil {
		return errors.New("uninitialized database")
	}

	return s.db.Close()
}

func (s *DatabaseStorage) Store(csp *CSPReportBody) error {
	if s.db == nil {
		return errors.New("uninitialized database")
	}

	docURL, err := url.Parse(csp.DocumentURI)
	if err != nil {
		return errors.Wrap(err, "could not insert invalid document URI")
	}

	hostName := strings.ToLower(docURL.Hostname())
	uri := strings.ToLower(docURL.EscapedPath())
	policy := strings.ToLower(csp.OriginalPolicy)
	directive := strings.ToLower(csp.ViolatedDirective)

	if err := s.insertHostname(hostName); err != nil {
		return errors.Wrap(err, "could not insert hostname")
	}

	if err := s.insertURI(hostName, uri); err != nil {
		return errors.Wrap(err, "could not insert uri")
	}

	if err := s.insertPolicy(hostName, policy); err != nil {
		return errors.Wrap(err, "could not insert policy")
	}

	if err := s.insertViolatedDirective(hostName, policy, directive); err != nil {
		return errors.Wrap(err, "could not insert violated directive")
	}

	return nil
}

func (s *DatabaseStorage) insertHostname(hostname string) (err error) {
	_, err = s.db.Exec(`
		INSERT INTO blocked_host (blh_hostname)
		SELECT ?
		WHERE NOT EXISTS (SELECT 1 FROM blocked_host WHERE blh_hostname = ?)
	`, hostname, hostname)

	return err
}

func (s *DatabaseStorage) insertURI(hostname, uri string) (err error) {
	_, err = s.db.Exec(`
		INSERT INTO blocked_uri (blu_uri, blu_host_id)
		SELECT ?, (SELECT blh_id FROM blocked_host WHERE blh_hostname = ?)
		WHERE NOT EXISTS (
			SELECT 1
			FROM blocked_uri
			WHERE blu_uri = ? AND blu_host_id = (
				SELECT blh_id FROM blocked_host WHERE blh_hostname = ?
			)
		)
	`, uri, hostname, uri, hostname)

	return err
}

func (s *DatabaseStorage) insertPolicy(hostname, policy string) (err error) {
	_, err = s.db.Exec(`
		INSERT INTO csp_policy (csp_policy, csp_hostname_id)
		SELECT ?, (SELECT blh_id FROM blocked_host WHERE blh_hostname = ?)
		WHERE NOT EXISTS (
			SELECT 1
			FROM csp_policy
			WHERE csp_policy = ? AND csp_hostname_id = (
				SELECT blh_id FROM blocked_host WHERE blh_hostname = ?
			)
		)
	`, policy, hostname, policy, hostname)

	return err
}

func (s *DatabaseStorage) insertViolatedDirective(hostname, policy, directive string) (err error) {
	_, err = s.db.Exec(`
		INSERT INTO csp_violated_directive (cvd_directive, cvd_csp_policy_id)
		SELECT ?, (
			SELECT csp_id
			FROM csp_policy
			WHERE csp_policy = ? AND csp_hostname_id = (
				SELECT blh_id FROM blocked_host WHERE blh_hostname = ?
			)
		)
		WHERE NOT EXISTS (
			SELECT 1
			FROM csp_violated_directive
			WHERE cvd_directive = ? AND cvd_csp_policy_id IN (
				SELECT 1
				FROM csp_policy
				WHERE csp_policy = ? AND csp_hostname_id = (
					SELECT blh_id FROM blocked_host WHERE blh_hostname = ?
				)
			)
		)
	`, directive, policy, hostname, directive, policy, hostname)

	return err
}
