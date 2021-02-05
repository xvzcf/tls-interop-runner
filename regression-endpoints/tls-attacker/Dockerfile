FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y openjdk-8-jdk && \
    apt-get install -y ant && \
    apt-get install maven -y && \
    apt-get install git -y && \
    apt-get install -y net-tools tcpdump ethtool iproute2 && \
    apt-get clean;

# RUN update-alternatives --config java

RUN git clone https://github.com/tls-attacker/TLS-Attacker.git /tls-attacker
RUN git clone https://github.com/tls-attacker/ASN.1-Tool.git /asn1-tool
RUN git clone https://github.com/tls-attacker/X509-Attacker.git /x509-attacker

ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64/
RUN export JAVA_HOME

WORKDIR /asn1-tool
RUN mvn clean install

WORKDIR /x509-attacker
RUN mvn clean install

WORKDIR /tls-attacker
RUN mvn clean install -DskipTests=true

WORKDIR /tls-attacker/resources
RUN chmod +x keygen.sh
RUN ./keygen.sh && cp *.pem ../apps

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
