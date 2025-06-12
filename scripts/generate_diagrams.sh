#!/bin/bash

# Install mermaid-cli if not already installed
npm install -g @mermaid-js/mermaid-cli

# Create temporary diagram files and convert them to PNG

# 1. System Architecture
cat << 'EOF' > temp_arch.mmd
graph TB
    subgraph User Interface Layer
        GUI[GUI Interface]
        CLI[CLI Interface]
        API[API Endpoint]
    end

    subgraph Core Processing
        RC[Rule Controller]
        TC[Template Controller]
        SC[Security Controller]
        MC[Monitoring Controller]
    end

    subgraph Security Modules
        IDS[IDS/IPS Module]
        DoS[DoS Protection]
        ST[State Tracking]
        TM[Template Manager]
    end

    subgraph System Integration
        IPT[iptables Interface]
        NF[Netfilter Hooks]
        LOG[Logging System]
        DB[Configuration DB]
    end

    GUI --> RC & TC & SC & MC
    CLI --> RC & TC & SC & MC
    API --> RC & TC & SC & MC

    RC --> IPT
    TC --> TM
    SC --> IDS & DoS
    MC --> LOG & ST

    IDS --> IPT
    DoS --> IPT
    ST --> NF
    TM --> DB

    IPT --> NF
    NF --> LOG
    LOG --> DB

    style GUI fill:#f9f,stroke:#333,stroke-width:4px
    style CLI fill:#f9f,stroke:#333,stroke-width:4px
    style API fill:#f9f,stroke:#333,stroke-width:4px
    style IDS fill:#ff9,stroke:#333,stroke-width:4px
    style DoS fill:#ff9,stroke:#333,stroke-width:4px
    style ST fill:#ff9,stroke:#333,stroke-width:4px
    style IPT fill:#9f9,stroke:#333,stroke-width:4px
    style NF fill:#9f9,stroke:#333,stroke-width:4px
    style LOG fill:#9f9,stroke:#333,stroke-width:4px
EOF

# 2. Network Stack Integration
cat << 'EOF' > temp_network.mmd
sequenceDiagram
    participant N as Network
    participant K as Kernel Space
    participant I as iptables
    participant B as BaselFirewall
    participant D as Database
    
    rect rgb(200, 220, 255)
    Note over N,D: Packet Journey
    N->>K: Incoming Packet
    K->>I: Pre-routing
    I->>B: Rule Check
    B->>D: Log Event
    end

    rect rgb(255, 220, 200)
    Note over N,D: Rule Processing
    B->>I: Apply Rules
    I->>K: Update Tables
    K->>N: Response
    end

    rect rgb(200, 255, 220)
    Note over N,D: State Tracking
    B->>B: Update Connection State
    B->>D: Store State
    B->>I: Update State Rules
    end
EOF

# 3. Packet Processing Flow
cat << 'EOF' > temp_packet.mmd
graph TD
    subgraph Packet Processing
        A[Incoming Packet] --> B{Check Source IP}
        B -->|Blocked IP| C[Drop Packet]
        B -->|Allowed IP| D{Check Port}
        
        D -->|Blocked Port| C
        D -->|Allowed Port| E{Check State}
        
        E -->|Invalid State| C
        E -->|Valid State| F{Rate Check}
        
        F -->|Rate Exceeded| C
        F -->|Rate OK| G[Accept Packet]
    end
    
    subgraph States
        H[NEW] --> I[ESTABLISHED]
        I --> J[RELATED]
        I --> K[CLOSED]
    end
    
    style C fill:#ff6666
    style G fill:#66ff66
EOF

# 4. Security Response Sequence
cat << 'EOF' > temp_security.mmd
sequenceDiagram
    participant P as Packet
    participant FW as Firewall Core
    participant IDS as IDS/IPS
    participant DoS as DoS Protection
    participant ST as State Tracking
    participant TM as Template Manager
    participant LOG as Logger

    Note over P,LOG: Initial Packet Processing
    P->>FW: Incoming Traffic
    FW->>ST: Check Connection State
    ST-->>FW: State Information

    Note over P,LOG: Security Analysis
    FW->>IDS: Deep Packet Inspection
    IDS->>IDS: Pattern Matching
    IDS->>IDS: Behavior Analysis
    IDS-->>FW: Threat Assessment

    Note over P,LOG: DoS Protection
    FW->>DoS: Rate Check
    DoS->>DoS: Connection Counting
    DoS->>DoS: Bandwidth Monitor
    DoS-->>FW: Rate Status
EOF

# 5. Template Management Flow
cat << 'EOF' > temp_template.mmd
graph TD
    subgraph Template Activation
        A[Select Template] --> B{Template Type}
        
        B -->|Web Server| C[Configure Web Ports]
        B -->|Database| D[Configure DB Ports]
        B -->|High Security| E[Lock Down Ports]
        B -->|VMware Block| F[Block VMware]
        
        C --> G[Enable HTTP/HTTPS]
        C --> H[Block Unused Ports]
        
        D --> I[Enable DB Ports]
        D --> J[Block Public Access]
        
        E --> K[Minimal Port Access]
        E --> L[Maximum Security]
        
        F --> M[Block MAC Address]
        F --> N[Block IP Range]
        
        G & H & I & J & K & L & M & N --> O[Apply Rules]
        O --> P[Verify Configuration]
        P --> Q[Log Changes]
    end
EOF

# Convert diagrams to PNG
mmdc -i temp_arch.mmd -o presentation/images/1_system_architecture.png -b transparent
mmdc -i temp_network.mmd -o presentation/images/2_network_stack.png -b transparent
mmdc -i temp_packet.mmd -o presentation/images/3_packet_processing.png -b transparent
mmdc -i temp_security.mmd -o presentation/images/4_security_response.png -b transparent
mmdc -i temp_template.mmd -o presentation/images/5_template_management.png -b transparent

# Clean up temporary files
rm temp_*.mmd

echo "Diagrams have been generated in presentation/images/" 