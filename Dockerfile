FROM oven/bun:1-debian

WORKDIR /app

COPY package.json index.ts ./

RUN apt-get update && apt-get install -y \
    curl \
    iptables \
    yara \
    unzip \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN bun install

CMD ["bun", "run", "index.ts"]