using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

// This code is only slightly modified from: https://github.com/klezVirus/SharpSelfDelete
// who did all the work creating this. Thus, the GPLv3 license also applies to this code as well.

namespace Selfdelete
{
    public class Program
    {
        public const string ads = ":adsads";
        public static void Main(string[] args)
        {
            string path = Process.GetCurrentProcess().MainModule.FileName;

            if (!args.Contains("--yes-pls-delete"))
            {
                Console.WriteLine("SelfDelete.exe - Delete the executable of the currently running process\n");
                Console.WriteLine($"The current process executable is: {path}");
                Console.WriteLine($"WARNING! Do not delete system executables!\n");
                Console.WriteLine("Usage: SelfDelete.exe --yes-pls-delete");
                return;
            }

            if (!string.IsNullOrEmpty(path))
            {
                Console.WriteLine($"[*] Attempting to delete current running executable file located at: {path}");
            }

            if (!File.Exists(path))
            {
                Console.WriteLine($"[-] Error: Cannot delete {path} because it does not exist! It may have already been deleted!");
                return;
            }

            IntPtr hCurrent = Win32.CreateFileW(path, (uint)0x80110000L, 0x1, IntPtr.Zero, (uint)3, (uint)0x80, IntPtr.Zero);

            if (hCurrent == IntPtr.Zero)
            {
                Console.WriteLine("[-] Unable to get handle to file!");
                return;
            }

            if (!RenameAds(hCurrent, ads))
            {
                Console.WriteLine("[-] Could not rename file!");
                return;
            }

            Win32.CloseHandle(hCurrent);

            hCurrent = Win32.CreateFileW(path, (uint)0x80110000L, 0x1, IntPtr.Zero, (uint)3, (uint)0x80, IntPtr.Zero);

            if (!MarkForDeletion(hCurrent))
            {
                Console.WriteLine("[-] Could not mark file for deletion!");
                return;
            }
            Win32.CloseHandle(hCurrent);

            if (File.Exists(path))
            {
                Console.WriteLine($"[-] Error: File could not be deleted! File {path} still exists!");
                return;
            }
            Console.WriteLine($"[+] File {path} was deleted successfully");
        }
        static bool MarkForDeletion(IntPtr fHandle)
        {
            var fileInformation = new Win32.FILE_DISPOSITION_INFO();
            fileInformation.DeleteFile = true;

            int bsize = Marshal.SizeOf(fileInformation);

            IntPtr pfi = Marshal.AllocHGlobal(bsize);

            Marshal.StructureToPtr(fileInformation, pfi, false);

            bool res = Win32.SetFileInformationByHandle(fHandle, Win32.FileInformationClass.FileDispositionInfo, pfi, bsize);
            Marshal.FreeHGlobal(pfi);
            return res;

        }
        static bool RenameAds(IntPtr fHandle, String newads)
        {
            Win32.FILE_RENAME_INFO fileInformation = new Win32.FILE_RENAME_INFO()
            {
                ReplaceIfExists = 0,
                RootDirectory = IntPtr.Zero,
                FileName = newads,
                FileNameLength = (uint)(Encoding.Unicode.GetBytes(newads).Length)
            };

            int bsize = Marshal.SizeOf(fileInformation);
            IntPtr pfi = Marshal.AllocHGlobal(bsize);
            Marshal.StructureToPtr(fileInformation, pfi, false);
            bool res = Win32.SetFileInformationByHandle(fHandle, Win32.FileInformationClass.FileRenameInfo, pfi, bsize);
            Marshal.FreeHGlobal(pfi);
            return res;
        }
    }

    public static class Win32
    {
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileW(string filename,
                                      uint desiredAccess,
                                      uint shareMode,
                                      IntPtr attributes,
                                      uint creationDisposition,
                                      uint flagsAndAttributes,
                                      IntPtr templateFile);
        public enum FileInformationClass : int
        {
            FileBasicInfo = 0,
            FileStandardInfo = 1,
            FileNameInfo = 2,
            FileRenameInfo = 3,
            FileDispositionInfo = 4,
            FileAllocationInfo = 5,
            FileEndOfFileInfo = 6,
            FileStreamInfo = 7,
            FileCompressionInfo = 8,
            FileAttributeTagInfo = 9,
            FileIdBothDirectoryInfo = 10, // 0xA
            FileIdBothDirectoryRestartInfo = 11, // 0xB
            FileIoPriorityHintInfo = 12, // 0xC
            FileRemoteProtocolInfo = 13, // 0xD
            FileFullDirectoryInfo = 14, // 0xE
            FileFullDirectoryRestartInfo = 15, // 0xF
            FileStorageInfo = 16, // 0x10
            FileAlignmentInfo = 17, // 0x11
            FileIdInfo = 18, // 0x12
            FileIdExtdDirectoryInfo = 19, // 0x13
            FileIdExtdDirectoryRestartInfo = 20, // 0x14
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct FILE_BASIC_INFO
        {
            public Int64 CreationTime;
            public Int64 LastAccessTime;
            public Int64 LastWriteTime;
            public Int64 ChangeTime;
            public UInt32 FileAttributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct FILE_DISPOSITION_INFO
        {
            public bool DeleteFile;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct FILE_RENAME_INFO
        {
            public uint ReplaceIfExists;
            public IntPtr RootDirectory;
            public uint FileNameLength; //this needs to be in bytes not chars
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string FileName;
        }

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetFileInformationByHandle(IntPtr handle, FileInformationClass fileinformationclass, IntPtr pfileinformation, int buffersize);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int MessageBox(IntPtr hWnd, String text, String caption, uint type);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
