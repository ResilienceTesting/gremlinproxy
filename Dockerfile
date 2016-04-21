FROM scratch
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
CMD ["gremlinproxy"]

# Expose ports.
EXPOSE 9876
