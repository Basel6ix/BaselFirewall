# BaselFirewall Architecture Diagrams

## System Architecture
```mermaid
graph TD
    A[Network Traffic] --> B[Packet Interceptor]
    B --> C[Core Engine]
    C --> D[Rule Engine]
    C --> E[Security Modules]
    E --> F[IDS/IPS]
    E --> G[DoS Protection]
    E --> H[NAT]
    C --> I[State Manager]
    C --> J[Logging System]
    K[GUI Interface] --> L[User Management]
    L --> M[Authentication]
    K --> N[Configuration]
    N --> O[Rule Management]
    K --> P[Monitoring]
    P --> Q[Alerts]
    P --> R[Logs]
```

## Data Flow
```mermaid
sequenceDiagram
    participant N as Network
    participant F as Firewall
    participant S as Security
    participant L as Logger
    participant U as User Interface

    N->>F: Incoming Packet
    F->>S: Security Check
    S->>F: Decision
    F->>L: Log Event
    L->>U: Update Display
    F-->>N: Forward/Drop
```

## User Authentication
```mermaid
sequenceDiagram
    participant U as User
    participant G as GUI
    participant A as Auth System
    participant D as Database
    participant S as Session

    U->>G: Login Request
    G->>A: Verify Credentials
    A->>D: Check Database
    D-->>A: User Data
    A->>S: Create Session
    S-->>G: Session Token
    G-->>U: Access Granted
```

## Security Module Interaction
```mermaid
graph LR
    A[Packet] --> B[IDS Scanner]
    B --> C{Threat?}
    C -->|Yes| D[Block]
    C -->|No| E[DoS Check]
    E --> F{Rate OK?}
    F -->|Yes| G[Allow]
    F -->|No| H[Rate Limit]
```

## Configuration Management
```mermaid
graph TD
    A[GUI] --> B[Config Manager]
    B --> C[File System]
    B --> D[Database]
    E[CLI] --> B
    B --> F[Validation]
    B --> G[Backup]
    B --> H[Version Control]
```

## Monitoring System
```mermaid
graph TD
    A[System Events] --> B[Event Collector]
    B --> C[Logger]
    C --> D[File Logs]
    C --> E[Database]
    F[Metrics] --> G[Monitor]
    G --> H[Dashboard]
    G --> I[Alerts]
```

## User Management
```mermaid
graph TD
    A[User Interface] --> B[User Manager]
    B --> C[Authentication]
    B --> D[Authorization]
    D --> E[Role Manager]
    E --> F[Permissions]
    B --> G[User Database]
```

## Network Processing
```mermaid
graph LR
    A[Network Interface] --> B[Packet Filter]
    B --> C[State Table]
    B --> D[NAT]
    B --> E[Rule Matcher]
    E --> F[Action]
    F --> G[Forward]
    F --> H[Drop]
    F --> I[Reject]
```

## Alert System
```mermaid
graph TD
    A[Security Events] --> B[Alert Manager]
    B --> C[Priority Queue]
    C --> D[Notification]
    D --> E[GUI Alert]
    D --> F[Email]
    D --> G[Log Entry]
```

## Backup System
```mermaid
graph TD
    A[Config Changes] --> B[Backup Manager]
    B --> C[Version Control]
    B --> D[Compression]
    D --> E[Storage]
    E --> F[Local Disk]
    E --> G[Remote Backup]
``` 