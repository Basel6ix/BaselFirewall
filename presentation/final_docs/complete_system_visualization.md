# BaselFirewall: Complete System Visualization

## 1. System Architecture Overview

### 1.1 Core Components Diagram
```mermaid
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
```

### 1.2 Network Stack Integration
```mermaid
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
```

## 2. Security Features

### 2.1 Packet Processing Flow
```mermaid
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
```

### 2.2 Security Response Sequence
```mermaid
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
```

## 3. Template System

### 3.1 Template Management Flow
```mermaid
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
```

## 4. Animation Sequences

### 4.1 System Initialization
1. Kernel Space Initialization
   - Load network drivers
   - Initialize iptables
   - Set up Netfilter hooks

2. BaselFirewall Startup
   - Load configuration
   - Initialize modules
   - Start monitoring

3. Service Integration
   - Connect to logging system
   - Initialize database
   - Start user interfaces

### 4.2 Attack Response Sequences

#### Port Scan Detection
1. Multiple Port Connection Attempts
   - Show connection patterns
   - Highlight suspicious ports
   - Display detection threshold

2. IDS Response
   - Pattern recognition
   - Alert generation
   - Rule updates

3. System Action
   - Block source IP
   - Log events
   - Admin notification

#### DoS Attack Response
1. Traffic Analysis
   - Show traffic spike
   - Connection counter
   - Bandwidth monitor

2. Protection Measures
   - Rate limiting
   - Connection dropping
   - IP blocking

3. System Recovery
   - Clear connection table
   - Update rules
   - Reset counters

#### VMware Attack Response
1. Detection Phase
   - MAC address identification
   - Traffic pattern analysis
   - Behavior monitoring

2. Response Phase
   - Apply VMware block template
   - Update firewall rules
   - Enable enhanced logging

3. Protection Phase
   - Block similar MAC ranges
   - Monitor virtualization signatures
   - Log all related activities

## 5. Technical Specifications

### 5.1 Network Integration
```
Kernel Level Integration:
- Netfilter hooks: PRE_ROUTING, POST_ROUTING
- iptables chains: INPUT, OUTPUT, FORWARD
- Connection tracking: nf_conntrack
- State management: conntrack_state
```

### 5.2 Security Modules
```
IDS/IPS Configuration:
- Pattern matching engine: regex, signature-based
- Behavior analysis: statistical anomaly detection
- Response mechanisms: block, alert, log

DoS Protection Settings:
- SYN flood protection: syn_rate_limit
- Connection limiting: conn_limit_per_ip
- Bandwidth monitoring: bw_monitor

State Tracking Parameters:
- Connection timeout: 3600s (default)
- UDP timeout: 30s
- ICMP timeout: 30s
- TCP established: 432000s
```

### 5.3 Template Configurations
```
Web Server Template:
- Allowed ports: 80, 443
- Blocked ports: 22, 23, 25
- Security features: all enabled

Database Template:
- Allowed ports: 3306, 5432
- Blocked ports: 80, 443, 22
- Security features: maximum

High Security Template:
- Allowed ports: 22 only
- Blocked ports: 1-1024 (except 22)
- Security features: maximum + logging

VMware Block Template:
- Block MAC pattern: 00:0c:29
- Block ports: all except essential
- Security features: maximum + monitoring
```

## 6. Implementation Notes

### 6.1 Performance Considerations
- Rule processing order optimization
- Connection state caching
- Template pre-compilation
- Log rotation and management

### 6.2 Security Best Practices
- Default deny policy
- Principle of least privilege
- Regular template updates
- Comprehensive logging
- Real-time monitoring

### 6.3 Maintenance Procedures
- Regular rule cleanup
- Log analysis
- Template verification
- Performance monitoring
- Security auditing 