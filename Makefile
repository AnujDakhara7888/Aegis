.PHONY: fmt fmt-check test race vet vectors check
fmt:
	gofmt -w internal
fmt-check:
	@test -z "$$(gofmt -l internal)" || (gofmt -l internal; exit 1)
test:
	go test ./...
race:
	go test -race ./...
vet:
	go vet ./...
vectors:
	python3 -m unittest discover -s scripts -p 'test_*.py' -v
check: fmt-check test race vet vectors
