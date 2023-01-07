# PPL Strip
A Windows 10/11 (Version Release ID 2009) PPL stripper

# Concept
Newer versions of Windows 10 & 11 by default add a layer of protection to the `lsass.exe` process called PPL.
PPL's primary objective is to stop untrusted/foreign processes from accessing a protected process, meaning the process' memory is also protected and any intrusive method such as this will be prevented... Which is annoying for hackers trying to dump lsass.
This doesn't just apply to `lsass.exe` - you can see which processes on Windows have PPL enabled from the following registry path:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\
```

Under this registry path is a list of keys containing values, one of which declares wether PPL is enabled or not (DWORD).

(Example of PPL being enabled on lsass.exe):

```powershell
PS> Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL


RunAsPPL     : 2
...
```

When enabled such as this, running anything such as `OpenProcess` on it with the following code (even with administrator rights and the debug privilege) will return 0, meaning it failed:

```c
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_process_id); //  0
```

(Any MiniDump based functions or software such as ProcDump or `MiniDumpWriteDump()` will also fail due to it relying on this function in most cases)
(`PROCESS_ALL_ACCESS` is an example, this will also fail with such flags as `PROCESS_QUERY_LIMITED_INFORMATION` etc.)

Even if you were to change the registry value, this would require a reboot to apply - it would perhaps work on a local home machine, but in a domain environment with GPOs applying, this registry value will be put back to normal as soon as the reboot occurs. Annoying.

This library uses a technique called BYOvD (Bring Your Own vulnerable Driver) to bypass this.
Drivers, when installed, (somewhat) have access to a portion of the Windows kernel where process memory is stored, including the bytes that define PPL protection on a running process. If overwriting the process' PPL bytes in the kernel memory is possible, we can overwrite this with null bytes to completely disable it without having to modify the registry.

Normally, a driver can't access another process' memory in the kernel, but a vulnerable driver (with arbitrary read/write exploits) can - this is where RTCore64.sys comes in.

# The Exploit
RTCore64.sys is a widely known driver for this specific reason. It was released by MSI a few years back for their AfterBurner utilities.
Later on, this driver was found to have the previously mentioned arbitrary read & write kernel vulnerability we are looking for.
Installing this driver and exploiting it allows us to overwrite other processes PPL protection memory in the kernel.

The PPL protection in Windows is defined in 4 bytes with the following definition:

```c
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;
            UCHAR Audit  : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;
```

This will be the target inside the kernel for a particular process with the protection.

# Why not make a custom driver?
Drivers in Windows must be signed and verified by Microsoft to be installed without removing driver installation policies which is really "unstealthy" for obvious reasons.
RTCore64 is signed and verified by Microsoft, therefore no additional protection needs to be removed to install it. I also don't feel like paying a few hundred dollars to get my own driver signed.

The DLL code in this repository (when attached to a process) installs the driver as a Windows kernel service pointing to the .sys file (and starts it), then gives every user full control over it. It then searches for `lsass.exe`'s process ID and disables the PPL protection in the kernel by overwriting the protection bytes to 4 null bytes (0x00).

__RUN THIS AS ADMIN!!!__

# Proof Of Concept

![image](https://user-images.githubusercontent.com/36815692/211118005-1b68c934-15d3-4699-ba7b-47339bb1ef7c.png)

Compiling and running the following code before the exploit:

```c
#include <stdio.h>
#include <Windows.h>

int main()
{
	DWORD dwLsassProcessId = 1124;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwLsassProcessId);

	printf("%ld\n", hProc);

	return 0;
}
```

![image](https://user-images.githubusercontent.com/36815692/211118647-1785f70c-c227-4e46-a5f5-a1eb0d5c3d5b.png)

(Injecting compiled DLL into `spoolsv.exe` using Process Hacker cos I'm a noob)

![image](https://user-images.githubusercontent.com/36815692/211118826-4db5ac68-0d42-4d8e-98a9-3cbb3fc7aec6.png)

Service being automatically created by DLL:

![image](https://user-images.githubusercontent.com/36815692/211118915-b087af5c-2e37-44d7-bef6-04e88a6b804a.png)

![image](https://user-images.githubusercontent.com/36815692/211119190-772a0dfc-cfd5-4aa3-a5a0-40c686d3d336.png)

Re-Running the same PoC code:

![image](https://user-images.githubusercontent.com/36815692/211119856-424a84f6-fe0e-414f-8aa6-7015270dd789.png)

I can now dump `lsass.exe`!

![image](https://user-images.githubusercontent.com/36815692/211120208-3ed11fba-d4f3-4900-8fee-d66076d00e43.png)
