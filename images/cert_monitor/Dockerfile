ARG SMI_FROM_LATEST_MINOR=dockerhub.cisco.com/smi-fuse-docker-internal/smi-libraries/releases/ubuntu-base/18.04.20/ubuntu-base:18.04.20
FROM ${SMI_FROM_LATEST_MINOR}

RUN apt-get-update && \
    apt-get install -y python3-pip && \
    cd /usr/local/bin && \
    ln -s /usr/bin/python3 python && \
    pip3 install --upgrade pip && \
    apt-cleanup
 
RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.14.2/bin/linux/amd64/kubectl && \
    chmod +x ./kubectl && \
    mv ./kubectl /usr/local/bin/kubectl

COPY cert-monitor.py /usr/local/bin

RUN chmod +x /usr/local/bin/cert-monitor.py
