FROM alpine:3.1

RUN mkdir /etc/gremlinproxy
RUN mkdir /var/log/gremlinproxy
ADD example-config.json /etc/gremlinproxy/

# Define mountable directories.
VOLUME ["/etc/gremlinproxy", "/var/log/gremlinproxy"]

# executable only
ADD gremlinproxy /usr/bin/

# Define working directory.
WORKDIR /etc/gremlinproxy

# Define default cmd
CMD ["gremlinproxy", "-c", "/etc/gremlinproxy/example-config.json"]

# Expose control port.
EXPOSE 9876

## IMPORTANT: expose all proxy ports that you want gremlinproxy to listen on for your application services (from the proxy block in config file)
EXPOSE 7777
