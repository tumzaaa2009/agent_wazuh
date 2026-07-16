FROM oven/bun:1

WORKDIR /app

COPY package.json boot.ts index.ts ./

RUN apt-get clean && \
    apt-get update && \
    apt-get install -y \
    iptables \
    yara \
    && rm -rf /var/lib/apt/lists/*

RUN bun install

CMD ["bun", "run", "boot.ts"]