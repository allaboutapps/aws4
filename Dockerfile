### -----------------------
# --- Stage: development
# --- https://hub.docker.com/_/golang
# --- https://github.com/microsoft/vscode-remote-try-go/blob/master/.devcontainer/Dockerfile
### -----------------------
FROM golang:1.14.2 AS development

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# https://github.com/go-modules-by-example/index/blob/master/010_tools/README.md#walk-through
ENV GOBIN /app/bin
ENV PATH $GOBIN:$PATH

# Our Makefile / env fully supports parallel job execution
ENV MAKEFLAGS "-j 8 --no-print-directory"

# Install required system dependencies
RUN apt-get update \
    && apt-get install -y \
    # https://github.com/microsoft/vscode-remote-try-go/blob/master/.devcontainer/Dockerfile#L24
    apt-utils \
    dialog \
    openssh-client \
    less \
    iproute2 \
    procps \
    lsb-release \
    # env specifics
    locales \
    sudo \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# env/vscode support: LANG must be supported, requires installing the locale package first
# https://github.com/Microsoft/vscode/issues/58015
# https://stackoverflow.com/questions/28405902/how-to-set-the-locale-inside-a-debian-ubuntu-docker-container
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8

ENV LANG en_US.UTF-8

# go richgo: (this package should NOT be installed via go get)
# https://github.com/kyoh86/richgo/releases
RUN mkdir -p /tmp/richgo \
    && cd /tmp/richgo \
    && wget https://github.com/kyoh86/richgo/releases/download/v0.3.3/richgo_0.3.3_linux_amd64.tar.gz \
    && tar xzf richgo_0.3.3_linux_amd64.tar.gz \
    && cp richgo /usr/local/bin/richgo \
    && rm -rf /tmp/richgo 

# go linting: (this package should NOT be installed via go get)
# https://github.com/golangci/golangci-lint#binary
# https://github.com/golangci/golangci-lint/releases
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b $(go env GOPATH)/bin v1.26.0

# linux permissions / vscode support: Add user to avoid linux file permission issues
# Detail: Inside the container, any mounted files/folders will have the exact same permissions
# as outside the container - including the owner user ID (UID) and group ID (GID). 
# Because of this, your container user will either need to have the same UID or be in a group with the same GID.
# The actual name of the user / group does not matter. The first user on a machine typically gets a UID of 1000,
# so most containers use this as the ID of the user to try to avoid this problem.
# 2020-04: docker-compose does not support passing id -u / id -g as part of its config, therefore we assume uid 1000
# https://code.visualstudio.com/docs/remote/containers-advanced#_adding-a-nonroot-user-to-your-dev-container
# https://code.visualstudio.com/docs/remote/containers-advanced#_creating-a-nonroot-user
ARG USERNAME=development
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd -s /bin/bash --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# vscode support: cached extensions install directory
# https://code.visualstudio.com/docs/remote/containers-advanced#_avoiding-extension-reinstalls-on-container-rebuild
RUN mkdir -p /home/$USERNAME/.vscode-server/extensions \
    /home/$USERNAME/.vscode-server-insiders/extensions \
    && chown -R $USERNAME \
    /home/$USERNAME/.vscode-server \
    /home/$USERNAME/.vscode-server-insiders

# linux permissions / vscode support: chown $GOPATH so $USERNAME can directly work with it
# Note that this should be the final step after installing all build deps 
RUN mkdir -p /$GOPATH/pkg && chown -R $USERNAME /$GOPATH

### -----------------------
# --- Stage: builder
### -----------------------

FROM development as builder
WORKDIR /app
COPY Makefile /app/Makefile
COPY go.mod /app/go.mod
COPY go.sum /app/go.sum
RUN make modules
COPY tools.go /app/tools.go
RUN make tools
COPY . /app/

### -----------------------
# --- Stage: builder-aws4
### -----------------------

FROM builder as builder-aws4
RUN make go-build