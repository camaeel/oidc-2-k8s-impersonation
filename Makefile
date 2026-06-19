all: test build

build:
	go build -o bin/ github.com/camaeel/oidc-2-k8s-impersonation/cmd/...
test:
	go test -coverprofile=coverage.out ./... 

vet:
	go vet ./...

lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

format:
	go fmt ./...
clean:
	rm -rf bin/ coverage.out

docker:
	docker build -t oidc-2-k8s-impersonation:local .

.PHONY: all build test vet lint format clean docker \
        dev-hosts dev-up dev-down dev-clean dev-logs dev-test
