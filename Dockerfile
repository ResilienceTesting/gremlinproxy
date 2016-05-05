FROM alpine:3.1

ADD example-config.json /opt/gremlinproxy/
ADD gremlinproxy /opt/gremlinproxy/
CMD ["/opt/gremlinproxy/gremlinproxy", "-c", "/opt/gremlinproxy/example-config.json"]

# Expose control port.
EXPOSE 9876

## IMPORTANT: expose all proxy ports that you want gremlinproxy to listen on for your application services (from the proxy block in config file)
EXPOSE 7777
