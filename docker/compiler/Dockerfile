FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        g++-i686-linux-gnu \
        g++-x86-64-linux-gnu \
        g++-arm-linux-gnueabihf \
        g++-aarch64-linux-gnu \
        g++-mingw-w64-i686-posix \
        g++-mingw-w64-x86-64-posix \
    && rm -rf /var/lib/apt/lists/*

COPY compile.py /opt/beru/compile.py
ENV LC_ALL=C HOME=/tmp
WORKDIR /src
ENTRYPOINT ["python3", "/opt/beru/compile.py"]
