ARG SMI_FROM_LATEST_MINOR=dockerhub.cisco.com/smi-fuse-docker-internal/smi-libraries/releases/ubuntu-base/18.04.11/ubuntu-base:18.04.11
FROM ${SMI_FROM_LATEST_MINOR}

RUN apt-get-update && \
    apt-get -y --no-install-recommends install curl ca-certificates git openssh-client && \
    apt-cleanup

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.14.2/bin/linux/amd64/kubectl && \
    chmod +x ./kubectl && \
    mv ./kubectl /usr/local/bin/kubectl

STOPSIGNAL SIGINT

COPY cert-monitor /usr/local/bin