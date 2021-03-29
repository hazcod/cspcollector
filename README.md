# cspcollector
Collects CSP reports and builds an exemption database.

## Testing
```shell
# first run our reporting server
% go run ./...

# now test it out
% curl --data '{                                   
  "csp-report": {
    "document-uri": "http://example.com/signup.html",
    "referrer": "",
    "blocked-uri": "http://example.com/css/style.css",
    "violated-directive": "style-src cdn.example.com",
    "original-policy": "default-src 'none'; style-src cdn.example.com; report-uri /_/csp-reports",
    "disposition": "report"
  }
}' -v http://localhost:8080

# should now be stored in csp.db
```
