# Domainwatchdog 🐶

[![Tests](https://github.com/joeig/domainwatchdog/workflows/Tests/badge.svg)](https://github.com/joeig/domainwatchdog/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/joeig/domainwatchdog)](https://goreportcard.com/report/github.com/joeig/domainwatchdog)

Domainwatchdog helps you to determine the availability of domains.

## Setup

    go install github.com/joeig/domainwatchdog/cmd/domainwatchdog@latest

## Usage

    $ domainwatchdog -domains "example.com,example.net,example.org,example5928474.de"
    status of domain "example.com": "domain is given"
    status of domain "example.net": "domain is given"
    status of domain "example.org": "domain is given"
    domain "example5928474.de" is available: "domain not found"

Domainwatchdog performs a whois lookup and matches the result with commonly used patterns that indicate if a certain domain is given or available.

### Exit codes

The exit codes harmonize nicely with [Icinga's check plugin API](https://icinga.com/docs/icinga-2/latest/doc/03-monitoring-basics/#check-result-state-mapping).

| Code | Description                      |
|-----:|----------------------------------|
|    0 | All domains are given            |
|    1 | Fatal error                      |
|    2 | At least one domain is available |
|    3 | Unknown error                    |