FROM python:3.10.16-bookworm

LABEL version="0.2"
LABEL description="NYUSEC Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3.10 \
    git \
    wget \
    libtool \
    texinfo \
    unzip    

RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02


WORKDIR /decoder
COPY entry.sh ./
RUN chmod +x entry.sh

#COPY pwndbg_2025.02.19_arm64.deb ./
#RUN apt install ./pwndbg_2025.02.19_arm64.deb
RUN git clone https://github.com/pwndbg/pwndbg  
WORKDIR /decoder/pwndbg  
RUN ./setup.sh


WORKDIR /decoder
ENTRYPOINT ["./entry.sh"]


# Sample run command:
# docker run -v ./decoder/:/decoder ./deployment/:/deployment -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder
