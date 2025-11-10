# -*- makefile -*-
# -----------------------------------------------------------------------
# Copyright 2022-2025 Open Networking Foundation Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------
# SPDX-FileCopyrightText: 2022-2024 Open Networking Foundation Contributors
# SPDX-License-Identifier: Apache-2.0
# -----------------------------------------------------------------------
# Intent: Build, test and release voltha-go-controller
# -----------------------------------------------------------------------
# Todo: Refactor common makefile logic and targets shared by
#       several VOLTHA repositories.
# -----------------------------------------------------------------------

GOLINT := golint
GOCMD = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app $(shell test -t 0 && echo "-it") -v gocache:/.cache -v gocache-${VOLTHA_TOOLS_VERSION}:/go/pkg voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-golang go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOTOOL=$(GOCMD) tool

# Static code analyzers
GOIMPORTS := goimports
GO_FILES := `find . -path vendor -prune -o -name '*.go'`
STATIC_TOOLS := $(GOLINT) $(GOFMT) $(GOIMPORTS)
#STATIC_TOOLS := $(GOFMT)

# set default shell
SHELL = bash -e -o pipefail

# Variables
VERSION                  ?= $(shell head -n 1 ./VERSION)
## Docker related
DOCKER_NAME := voltha-go-controller
DOCKER_LABEL_VCS_DIRTY     = false
ifneq ($(shell git ls-files --others --modified --exclude-standard 2>/dev/null | wc -l | sed -e 's/ //g'),0)
    DOCKER_LABEL_VCS_DIRTY = true
endif
DOCKER_EXTRA_ARGS        ?=
DOCKER_REGISTRY          ?=
DOCKER_REPOSITORY        ?= voltha/
DOCKER_TAG               ?= ${VERSION}$(shell [[ ${DOCKER_LABEL_VCS_DIRTY} == "true" ]] && echo "-dirty" || true)
IMAGENAME                := ${DOCKER_REGISTRY}${DOCKER_REPOSITORY}voltha-go-controller:${DOCKER_TAG}
DOCKER_TARGET            ?= prod

## Docker labels. Only set ref and commit date if committed
DOCKER_LABEL_VCS_URL       ?= $(shell git remote get-url $(shell git remote))
DOCKER_LABEL_VCS_REF       = $(shell git rev-parse HEAD)
DOCKER_LABEL_BUILD_DATE    ?= $(shell date -u "+%Y-%m-%dT%H:%M:%SZ")
DOCKER_LABEL_COMMIT_DATE   = $(shell git show -s --format=%cd --date=iso-strict HEAD)
DOCKER_BUILD_ARGS ?= \
	${DOCKER_EXTRA_ARGS} \
	--build-arg org_label_schema_version="${VERSION}" \
	--build-arg org_label_schema_vcs_url="${DOCKER_LABEL_VCS_URL}" \
	--build-arg org_label_schema_vcs_ref="${DOCKER_LABEL_VCS_REF}" \
	--build-arg org_label_schema_build_date="${DOCKER_LABEL_BUILD_DATE}" \
	--build-arg org_opencord_vcs_commit_date="${DOCKER_LABEL_COMMIT_DATE}" \
	--build-arg org_opencord_vcs_dirty="${DOCKER_LABEL_VCS_DIRTY}"


COVERAGE_DIR = ./tests/results
COVERAGE_PROFILE = $(COVERAGE_DIR)/profile.out
TEST_TARGETS := test-default test-verbose test-short
test-short: ARGS=-short
test-verbose: ARGS=-v
# tool containers
VOLTHA_TOOLS_VERSION ?= 3.1.4

HADOLINT          = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app $(shell test -t 0 && echo "-it") voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-hadolint hadolint
GOLANGCI_LINT     = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app $(shell test -t 0 && echo "-it") -v gocache:/.cache -v gocache-${VOLTHA_TOOLS_VERSION}:/go/pkg voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-golangci-lint golangci-lint
GO_JUNIT_REPORT   = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app -i voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-go-junit-report go-junit-report
GOCOVER_COBERTURA = docker run --rm --user $$(id -u):$$(id -g) -v ${CURDIR}:/app/src/github.com/opencord/voltha-openolt-adapter -i voltha/voltha-ci-tools:${VOLTHA_TOOLS_VERSION}-gocover-cobertura gocover-cobertura

## Local Development Helpers
local-protos: ## Copies a local version of the voltha-protos dependency into the vendor directory
ifdef LOCAL_PROTOS
	rm -rf vendor/github.com/opencord/voltha-protos/v5/go
	mkdir -p vendor/github.com/opencord/voltha-protos/v5/go
	cp -r ${LOCAL_PROTOS}/go/* vendor/github.com/opencord/voltha-protos/v5/go
	rm -rf vendor/github.com/opencord/voltha-protos/v5/go/vendor
endif

local-lib-go: ## Copies a local version of the voltha-lib-go dependency into the vendor directory
ifdef LOCAL_LIB_GO
	mkdir -p vendor/github.com/opencord/voltha-lib-go/v7/pkg
	cp -r ${LOCAL_LIB_GO}/pkg/* vendor/github.com/opencord/voltha-lib-go/v7/pkg/
endif

# This should to be the first and default target in this Makefile
help :: ## Print help for each Makefile target
	@echo "Usage: make [<target>]"
	@echo "where available targets are:"
	@echo
	@grep '^[[:alpha:]_-]*:.* ##' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN {FS=":.* ## "}; {printf "%-25s : %s\n", $$1, $$2};'


exe:
	@echo Building voltha-go-controller....
	@cd voltha-go-controller && go build

vgcctl:
	@echo Building vgcctl....
	@cd voltha-go-controller/cli && go build -o vgcctl

docker-build:
	@echo Building Docker $(DOCKER_NAME)....
	docker build $(DOCKER_BUILD_ARGS) --target=${DOCKER_TARGET} -t $(IMAGENAME) -f docker/Dockerfile.voltha-go-controller .
ifdef BUILD_PROFILED
	docker build $(DOCKER_BUILD_ARGS) --target=dev --build-arg EXTRA_GO_BUILD_TAGS="-tags profile" -t ${IMAGENAME}-profile -f docker/Dockerfile.voltha-go-controller .
endif
ifdef BUILD_RACE
	docker build $(DOCKER_BUILD_ARGS) --target=dev --build-arg EXTRA_GO_BUILD_TAGS="-race" -t ${IMAGENAME}-rd -f docker/Dockerfile.voltha-go-controller .
endif

docker-push: ## Push the docker images to an external repository
	docker push ${IMAGENAME}
ifdef BUILD_PROFILED
	docker push ${IMAGENAME}-profile
endif
ifdef BUILD_RACE
	docker push ${IMAGENAME}-rd
endif

docker: exe vgcctl
	@echo Building Docker $(DOCKER_NAME)....
	sudo docker build --platform=linux/amd64 -t $(IMAGENAME) -f docker/Dockerfile.voltha-go-controller .

## Docker targets
build:	local-protos local-lib-go docker  ## Build voltha-go-controller image

build-docker-profile: sca exe-profile vgcctl
	@echo Building Docker $(DOCKER_NAME)....
	sudo docker build -t $(IMAGENAME)-profile -f docker/Dockerfile.voltha-go-controller .

sca: ## Runs static code analysis with the golangci-lint tool
	@rm -rf ./sca-report
	@mkdir -p ./sca-report
	@echo "Running static code analysis..."
	@${GOLANGCI_LINT} run --output.text.path=stdout --output.junit-xml.path=./sca-report/sca-report.xml ./...
	@echo ""
	@echo "Static code analysis OK"

clean :: ## Removes any local filesystem artifacts generated by a build
	rm -f voltha-go-controller/voltha-go-controller
	rm -f voltha-go-controller/cli/vgcctl

mock-gen:
	mockery -dir intf/ -name DatabaseIntf -structname MockDb -filename MockDatabase.go

## lint and unit tests
lint-dockerfile: ## Perform static analysis on Dockerfile
	@echo "Running Dockerfile lint check ..."
	@${HADOLINT} $$(find . -name "Dockerfile.*" -not -path "./vendor/*")
	@echo "Dockerfile lint check OK"

lint-mod: ## Verify the Go dependencies
	@echo "Running dependency check..."
	@${GOCMD} mod verify
	@echo "Dependency check OK. Running vendor check..."
	@git status > /dev/null
	@git diff-index --quiet HEAD -- go.mod go.sum vendor || (echo "ERROR: Staged or modified files must be committed before running this test" && git status -- go.mod go.sum vendor && exit 1)
	@[[ `git ls-files --exclude-standard --others go.mod go.sum vendor` == "" ]] || (echo "ERROR: Untracked files must be cleaned up before running this test" && git status -- go.mod go.sum vendor && exit 1)
	${GOCMD} mod tidy
	${GOCMD} mod vendor
	@git status > /dev/null
	@git diff-index --quiet HEAD -- go.mod go.sum vendor || (echo "ERROR: Modified files detected after running go mod tidy / go mod vendor" && git status -- go.mod go.sum vendor && git checkout -- go.mod go.sum vendor && exit 1)
	@[[ `git ls-files --exclude-standard --others go.mod go.sum vendor` == "" ]] || (echo "ERROR: Untracked files detected after running go mod tidy / go mod vendor" && git status -- go.mod go.sum vendor && git checkout -- go.mod go.sum vendor && exit 1)
	@echo "Vendor check OK."

lint: local-lib-go lint-mod lint-dockerfile ## Run all lint targets

mod-update: ## Update go mod files
	${GOCMD} mod tidy
	${GOCMD} mod vendor

test: ## Run unit tests
	@mkdir -p ./tests/results
	@${GOCMD} test -mod=vendor -v -coverprofile ./tests/results/go-test-coverage.out -covermode count ./... 2>&1 | tee ./tests/results/go-test-results.out ;\
	RETURN=$$? ;\
	${GO_JUNIT_REPORT} < ./tests/results/go-test-results.out > ./tests/results/go-test-results.xml ;\
	${GOCOVER_COBERTURA} < ./tests/results/go-test-coverage.out > ./tests/results/go-test-coverage.xml ;\
	exit $$RETURN

## -----------------------------------------------------------------------
## -----------------------------------------------------------------------
pre-commit : .venv
	source .venv/bin/activate && pre-commit

## -----------------------------------------------------------------------
## [TODO] Replace inlined target with repo:onf-make/makefiles/virtualenv/
## -----------------------------------------------------------------------
venv : .venv
.venv :
	virtualenv -p python3 $@
	$@/bin/pip install -r requirements.txt

## -----------------------------------------------------------------------
## -----------------------------------------------------------------------
help ::
	@printf '  %-33.33s %s\n' 'pre-commit' \
	  'Invoke the pre-commit hook linting tool'

clean ::
	$(RM) -r .venv

# [EOF]
