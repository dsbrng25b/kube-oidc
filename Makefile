#
# kube-oidc Makefile
#

BINARY_NAME=kube-oidc
VERSION=`git describe --tags --dirty --always`
GIT_COMMIT=`git rev-parse HEAD`
BUILD_TIME=`date -Isec`
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.buildTime=${BUILD_TIME}"

build:
	go build -o ${BINARY_NAME} ${LDFLAGS} .
	GOOS=windows GOARCH=amd64 go build -o ${BINARY_NAME}.exe ${LDFLAGS} .
	GOOS=darwin GOARCH=amd64 go build -o ${BINARY_NAME}-darwin ${LDFLAGS} .

clean:
	rm -f ${BINARY_NAME} ${BINARY_NAME}.exe

.PHONY: clean
