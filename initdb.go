package main

import "github.com/pkg/errors"

func (s *DatabaseStorage) InitializeDatabase() error {
	if _, err := s.db.Exec(`

		CREATE TABLE IF NOT EXISTS blocked_host (
			blh_id			integer	NOT NULL PRIMARY KEY,
			blh_hostname	text	NOT NULL,
	
			UNIQUE(blh_hostname)
		);
		
		CREATE INDEX IF NOT EXISTS idx_blocked_host_blh_hostname ON blocked_host (blh_hostname);

		CREATE TABLE IF NOT EXISTS blocked_uri (
			blu_id		integer	NOT NULL PRIMARY KEY,
			blu_uri		text	NOT NULL,
			blu_host_id int		NOT NULL REFERENCES blocked_host(blh_id),

			UNIQUE(blu_host_id, blu_uri)
		);

		CREATE INDEX IF NOT EXISTS idx_blocked_uri_blu_uri ON blocked_uri (blu_uri);

		CREATE TABLE IF NOT EXISTS csp_policy (
			csp_id		integer		NOT NULL PRIMARY KEY,
			csp_hostname_id int		NOT NULL REFERENCES blocked_host(blh_id),
			csp_policy text			NOT NULL,

			UNIQUE(csp_policy, csp_hostname_id)
		);

		CREATE TABLE IF NOT EXISTS csp_violated_directive (
			cvd_id		integer		NOT NULL PRIMARY KEY,
			cvd_csp_policy_id int 	NOT NULL REFERENCES csp_policy(csp_id),
			cvd_directive text		NOT NULL,

			UNIQUE(cvd_csp_policy_id, cvd_directive)
		);

	`); err != nil {
		return errors.Wrap(err, "could not create tables")
	}

	return nil
}
