# Dockerfile for the TouchSign GitHub Action.
#
# NOTE: this Dockerfile has not been built or run. It is written to express
# the intended build, not verified against an actual `docker build`. When it
# is eventually built, `go mod tidy` should be run first (see README.md) so
# that a go.sum exists for the build stage to use with real dependency
# verification.

FROM golang:1.24-alpine AS build

WORKDIR /src

# Copy module files first so dependency resolution is cached independently
# of source changes. Note there is no go.sum yet (see go.mod) -- once one
# exists it should be copied here too, e.g.:
#   COPY go.mod go.sum ./
COPY go.mod ./

COPY . .

# `go mod tidy` has deliberately NOT been run as part of scaffolding this
# project (see README.md / go.mod comments). It would need to run here, or
# be run once ahead of time with a committed go.sum, before this build
# actually succeeds.
RUN go mod tidy && \
    CGO_ENABLED=0 go build -o /out/touchsign ./cmd/touchsign

# ---

FROM alpine:3.20

# git itself is required at runtime: TouchSign shells out to `git
# verify-commit`, `git log`, `git rev-list`, and `git diff` rather than
# reimplementing any of that logic.
RUN apk add --no-cache git openssh-keygen ca-certificates

COPY --from=build /out/touchsign /usr/local/bin/touchsign

ENTRYPOINT ["/usr/local/bin/touchsign"]
CMD ["check", "--repo", "/github/workspace"]
