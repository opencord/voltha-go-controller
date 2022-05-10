# SPDX-FileCopyrightText: ${today.year}-present Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

# set default shell
SHELL = bash -e -o pipefail

# Variables
VERSION                    ?= $(shell cat ./VERSION)

# tool containers
VOLTHA_TOOLS_VERSION ?= 2.4.0

GO                = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app $(shell test -t 0 && echo "-it") -v gocache:/.cache -v gocache-${VOLTHA_TOOLS_VERSION}:/go/pkg voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-golang go
GO_JUNIT_REPORT   = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app -i voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-go-junit-report go-junit-report
GOCOVER_COBERTURA = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app/src/github.com/opencord/bbsim-sadis-server -i voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-gocover-cobertura gocover-cobertura
GOLANGCI_LINT     = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app $(shell test -t 0 && echo "-it") -v gocache:/.cache -v gocache-${VOLTHA_TOOLS_VERSION}:/go/pkg voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-golangci-lint golangci-lint
HADOLINT          = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app $(shell test -t 0 && echo "-it") voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-hadolint hadolint

## lint and unit tests

lint:
	@echo "Add lint command for Dockerfile and go modules, see https://github.com/opencord/bbsim-sadis-server/blob/master/Makefile#L83-L103"

sca:
	@echo "Add static code analysis command for Go code, see https://github.com/opencord/bbsim-sadis-server/blob/master/Makefile#L105-L111"

test:
	@echo "Add unit test command for Go code, see https://github.com/opencord/bbsim-sadis-server/blob/master/Makefile#L113-L119"