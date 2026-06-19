FROM oven/bun:1

WORKDIR /app

COPY package.json index.ts ./

# Install iptables for blocking functionality
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

# Add wazuh user and group to match host for agent_control permissions
RUN groupadd -g 125 wazuh && useradd -u 115 -g 125 -s /sbin/nologin wazuh

# Run bun install
RUN bun install

# Command requires root privileges for iptables
# In production, run with --cap-add=NET_ADMIN
CMD ["bun", "run", "index.ts"]
