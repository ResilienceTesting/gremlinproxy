all: gremlinproxy gremlinexampleapp
gremlinproxy:
	docker run --rm -v "$PWD":/usr/src/gremlinproxy -w /usr/src/gremlinproxy golang:alpine go build -v
gremlinexampleapp: gremlinproxy
	docker build -t gremlinexampleapp .
