# Instructions to build a SQL Server 2022 container with systemd and SSH
#
# Run:
# docker buildx build . --platform linux/amd64 -t sql22_u2204:latest

FROM ubuntu:22.04

# Update packages
RUN apt-get update && apt-get upgrade -y

# Install systemd for systemctl
RUN apt-get install -y systemd systemd-sysv

# Install openssh-server
RUN apt-get install -y openssh-server && \
    mkdir -p /var/run/sshd && \
    systemctl enable ssh

# Install vim
RUN apt-get install -y vim

# Install net-tools (ifconfig, telnet, ip address)
RUN apt-get install -y net-tools iputils-ping telnet iproute2

# Install dependencies for SQL Server
RUN apt-get install -y curl gnupg2 software-properties-common

# Import SQL Server public repository GPG keys
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

# Register the SQL Server Ubuntu repository
RUN add-apt-repository "$(curl https://packages.microsoft.com/config/ubuntu/22.04/mssql-server-2022.list)"

# Install SQL Server
RUN apt-get update && apt-get install -y mssql-server

# Configure SQL Server
RUN mkdir -p /var/opt/mssql/data && \
    chown mssql:mssql /var/opt/mssql/data && \
    mkdir -p /var/opt/mssql/log && \
    chown mssql:mssql /var/opt/mssql/log && \
    mkdir -p /var/opt/mssql/secrets && \
    chown mssql:mssql /var/opt/mssql/secrets

## See doc at https://learn.microsoft.com/en-us/sql/linux/quickstart-install-connect-ubuntu?view=sql-server-ver16&tabs=ubuntu2204

## Create SQL Server setup script
# RUN echo '#!/bin/bash \n\
#/opt/mssql/bin/mssql-conf setup accept-eula \n\
#systemctl enable mssql-server.service \n\
#systemctl start mssql-server.service \n' > /setup-sql.sh && \
#    chmod +x /setup-sql.sh
#
## Install SQL Server command-line tools
#RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
#    curl https://packages.microsoft.com/config/ubuntu/22.04/prod.list | tee /etc/apt/sources.list.d/msprod.list && \
#    apt-get update && \
#    echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections && \
#    ACCEPT_EULA=Y apt-get install -y mssql-tools unixodbc-dev

# Add SQL Server tools to PATH
ENV PATH="$PATH:/opt/mssql-tools/bin"

# Clean up apt cache
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Keep systemd from starting too many processes
RUN rm -f /lib/systemd/system/multi-user.target.wants/* \
    /etc/systemd/system/*.wants/* \
    /lib/systemd/system/local-fs.target.wants/* \
    /lib/systemd/system/sockets.target.wants/*udev* \
    /lib/systemd/system/sockets.target.wants/*initctl* \
    /lib/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup* \
    /lib/systemd/system/systemd-update-utmp*

# Preserve SQL Server systemd service
RUN mkdir -p /lib/systemd/system/multi-user.target.wants/ && \
    ln -sf /lib/systemd/system/mssql-server.service /lib/systemd/system/multi-user.target.wants/mssql-server.service

# Set systemd as entrypoint (PID 1)
ENTRYPOINT ["/lib/systemd/systemd"]
CMD ["systemd.unit=multi-user.target"]

# Setup SQL Server on first run
RUN systemctl enable mssql-server

# Expose SQL Server and SSH ports
EXPOSE 1433 22

# Create a startup script to ensure SQL Server is configured
RUN echo '#!/bin/bash \n\
if [ ! -f /var/opt/mssql/initialized ]; then \n\
  /opt/mssql/bin/mssql-conf setup accept-eula \n\
  touch /var/opt/mssql/initialized \n\
fi \n\
exec "$@" \n' > /startup.sh && \
    chmod +x /startup.sh

ENTRYPOINT ["/startup.sh", "/lib/systemd/systemd"]
