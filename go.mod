module github.com/mstone/touchsign

go 1.24

// NOTE: `go mod tidy` has not been run against this module and there is no
// go.sum committed alongside it. The versions below are plausible, recent
// pins for the two direct dependencies this project is designed against;
// they have not been resolved or downloaded. Running `go mod tidy` (or
// `go build ./...`) is the expected next step before this module will
// actually compile.
require (
	github.com/google/go-github/v66 v66.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/google/go-querystring v1.1.0 // indirect
