FROM oven/bun:1

WORKDIR /app

COPY package.json boot.ts index.ts ./

RUN apt-get clean && \
    apt-get update -o Acquire::Check-Valid-Until=false --allow-releaseinfo-change && \
    apt-get install -y \
    curl \
    iptables \
    yara \
    unzip \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN bun install

CMD ["bun", "run", "boot.ts"]