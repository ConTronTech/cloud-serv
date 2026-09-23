FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# libasio-dev: Crow's networking. libssl-dev: password hashing / SHA-256 / CSPRNG.
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    make \
    libasio-dev \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source
COPY . .

# Build
RUN make clean && make

# config.env is untracked (it holds secrets); fall back to the example so a fresh
# clone still builds. Mount or bake your real config.env over this for real use.
RUN cp -n config.env.example config.env

# Runtime data dir (SQLite DB + uploaded blobs)
RUN mkdir -p data

EXPOSE 8080

ENTRYPOINT ["./cloud_serv", "config.env"]
