# MemScanner - Cross-Platform In-Memory Threat Detection

**MemScanner** is a lightweight, zero-dependency agent for Windows and Linux that detects fileless process migration and in-memory threats by analyzing process lineage, memory protections, and module signatures. Built for research and SOC environments targeting Meterpreter T1055.003 and similar TTPs.
Modern adversaries increasingly rely on fileless, in-memory tactics to evade traditional endpoint security. In Meterpreter-based intrusions, the initial payload executes inside a short-lived, exploit-spawned process. To maintain persistence and avoid losing command-and-control C2 access when that process terminates, attackers leverage the `migrate` command to inject shellcode into stable, trusted Windows processes such as `explorer.exe` and `svchost.exe` [2].

This technique maps to MITRE ATT&CK T1055.003: Process Injection - Thread Execution Hijacking [1]. By residing solely in memory within a legitimate process, the malicious code bypasses disk-based antivirus and signature detection [1].

Post-migration, the injected shellcode requires RWX Read-Write-Execute memory regions to execute, a configuration actively blocked by Data Execution Prevention DEP in legitimate software [5]. Additionally, injected modules typically lack valid Microsoft signatures, creating detectable anomalies in code signing validation [3][4].

File-based EDR/AV solutions therefore fail to detect these TTPs. This creates a critical gap for behavioral and memory-based monitoring capable of identifying: 1. Orphaned processes, 2. Abnormal parent-child process trees, 3. Unsigned modules in trusted processes, 4. Suspicious RWX memory allocations.

To address the detection gap created by fileless process migration, MemScanner performs real-time behavioral and memory telemetry collection without relying on disk signatures.

The agent operates on the principle that while malicious code can hide its file, it cannot hide its *behavior* in memory. MemScanner continuously monitors endpoints and flags anomalies that correlate with Meterpreter migration and T1055.003 execution [1]:
1. **Process Lineage Analysis** for orphaned/suspicious parent-child relationships [2]
2. **Memory Protection Scanning** for RWX regions required by shellcode [5]
3. **Module Signature Validation** for unsigned or non-Microsoft modules [3][4]
4. **Suspicious Path & Name Heuristics** for temp directories and randomized names

Telemetry is sent via authenticated HTTPS to a central server for correlation and alerting. This moves detection from "file-based" to "behavior + memory-based".

### Key Features

#### 1. Cross-Platform Agents
- **Windows**: `agents/meterpreter_agent.ps1` - PowerShell 5.1+. Uses Win32 APIs via Add-Type to enumerate processes, memory regions, and modules. Includes GUI popup for config input.
- **Linux**: `agents/meterpreter_agent.sh` - Bash. Parses `/proc/*/maps`, `/proc/*/status`, `/proc/*/cmdline` for equivalent telemetry.
- Both support CLI params, interactive prompts, and JSON config file for one-time setup.

#### 2. Process Lineage & Anomaly Detection
Flags suspicious parent-child relationships that indicate post-exploitation migration:
- Windows: `explorer.exe` spawned by `powershell.exe`, `mshta.exe`, `rundll32.exe` [2]
- Linux: `systemd`, `sshd`, `bash` with unexpected PPID or from temp paths
- Detects orphaned processes and name/path mismatches

#### 3. Memory Protection Analysis
Scans for RWX Read-Write-Execute regions required for shellcode execution [5]:
- Windows: `VirtualQueryEx` API to find `PAGE_EXECUTE_READWRITE` regions
- Linux: Parses `/proc/PID/maps` for `rwxp` mappings
- Reports base address, size, and protection flags

#### 4. Module/Library Validation
Verifies code integrity to catch injected payloads:
- Windows: `EnumProcessModules` + Authenticode signature check [3][4]
- Linux: Lists shared objects from `/proc/PID/maps`, validates ELF paths
- Flags unsigned modules and libraries in temp/non-standard paths

#### 5. Secure Telemetry
- HTTPS POST with API key auth to configurable server URL
- JSON payload: hostname, process tree, memory anomalies, modules, timestamp
- Offline buffering + retry if server unreachable

#### 6. Zero-Dependency Deployment
- No kernel drivers, no compiled binaries
- Runs on standard PowerShell 5.1+ / Bash 4.0+
- Admin/root only needed for full scans of protected processes
- <10KB per agent
