using System;
using System.Collections.Generic;
using System.Collections;
using System.Security;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

// Return codes (incomplete):
// 0 = text data
// 1 = download
// 2 = screenshot
// 3 = set_pwd

namespace Filesystem
{
    public class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("Filesystem options:");
                Console.WriteLine("cd, cat, ls, pwd, mkdir, rm, cp, upload, download");
                Console.WriteLine("To view help for a sub-command, do Filesystem.exe <cmd> -h");
                return 0;
            }
            string cmd = args[0].ToLower();
            args = args.Skip(1).Take(args.Length).ToArray(); // cut off the first element in the args[] array
            switch (cmd)
            {
                case "cat":
                    return Cat(args);
                case "cp":
                    return Cp(args);
                case "ls":
                    return Ls(args);
                case "mkdir":
                    return Mkdir(args);
                case "pwd":
                    return Pwd(args);
                case "cd":
                    return Cd(args);
                case "rm":
                    return Rm(args);
                default:
                    Console.WriteLine("[!] Invalid sub-command selection: " + cmd);
                    return 0;
            }
        }

        static int Cat(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("cat <file> [file2] [file3] ...");
                return 0;
            }

            ArrayList fileTexts = new ArrayList();
            foreach (string file in args)
            {
                try
                {
                    fileTexts.Add(File.ReadAllText(file));
                }
                catch (FileNotFoundException)
                {
                    Console.WriteLine("[!] Error: file not found: " + file);
                }
                catch (SecurityException)
                {
                    Console.WriteLine("[!] Error: no permissions to read file: " + file);
                }
                catch (IOException)
                {
                    Console.WriteLine("[!] Error: file could not be read: " + file);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Error: Unexpected error reading file: " + file);
                    Console.WriteLine(e);
                }
            }
            if (fileTexts.Count != 0)
            {
                foreach (string fileText in fileTexts)
                {
                    Console.WriteLine(fileText);
                }
            }
            return 0;
        }

        static int Cp(string[] args)
        {
            bool CheckParams(string s, string d)
            {
                s = Path.GetFullPath(s);
                d = Path.GetFullPath(d);
                FileAttributes fatributes;
                try
                {
                    fatributes = File.GetAttributes(s);
                }
                catch (FileNotFoundException)
                {
                    Console.WriteLine("[!] Error: source file not found: " + s);
                    return false;
                }
                catch (DirectoryNotFoundException)
                {
                    Console.WriteLine("[!] Error: source directory not found: " + s);
                    return false;
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Error: not authorized to access: " + s);
                    return false;
                }
                catch (IOException)
                {
                    Console.WriteLine("[!] Error: the source file is locked by another process: " + s);
                    return false;
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Error: unexpected exception with source: " + s);
                    Console.WriteLine(e);
                    return false;
                }
                return true;
            }
            // Taken from MSDN (https://docs.microsoft.com/en-us/dotnet/standard/io/how-to-copy-directories?redirectedfrom=MSDN)
            bool DirectoryCopy(string sourceDirName, string destDirName, bool copySubDirs)
            {
                // Get the subdirectories for the specified directory.
                DirectoryInfo dir = new DirectoryInfo(sourceDirName);

                if (!dir.Exists)
                {
                    throw new DirectoryNotFoundException("[!] Error: source directory does not exist or could not be found: " + sourceDirName);
                }

                DirectoryInfo[] dirs = dir.GetDirectories();
                // If the destination directory doesn't exist, create it.
                if (!Directory.Exists(destDirName))
                {
                    try
                    {
                        Directory.CreateDirectory(destDirName);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("[!] Error: unauthorized to create destination directory: " + destDirName);
                        return false;
                    }
                }

                // Get the files in the directory and copy them to the new location.
                FileInfo[] files = dir.GetFiles();
                foreach (FileInfo file in files)
                {
                    string temppath = Path.Combine(destDirName, file.Name);
                    try
                    {
                        file.CopyTo(temppath, overwrite: true);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("[!] Error: unauthorized to copy file " + file.Name + " to destination");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Error: unexpected exception when copying file: " + file.Name);
                        Console.WriteLine(e);
                    }

                }

                // If copying subdirectories, copy them and their contents to new location.
                if (copySubDirs)
                {
                    foreach (DirectoryInfo subdir in dirs)
                    {
                        string temppath = Path.Combine(destDirName, subdir.Name);
                        DirectoryCopy(subdir.FullName, temppath, copySubDirs);
                    }
                }
                return true;
            }

            // start Cp execution here
            if (args.Length != 2 || (args.Length == 2 && (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")))
            {
                Console.WriteLine("cp <source> <destination>");
                Console.WriteLine("Source and destination can be files or folders");
                return 0;
            }
            // Handle errors such as file doesn't exist or no permissions
            string source = Path.GetFullPath(args[0]);
            string dest = Path.GetFullPath(args[1]);
            bool overwrite = false;
            if (!CheckParams(source, dest))
            {
                return 0;
            }

            if (Directory.Exists(dest))
            {
                // User specified <file> <directory> so we need to append the file name to the dest directory
                dest = Path.Combine(dest, Path.GetFileName(source));
            }
            if (Directory.Exists(source))
            {
                if (DirectoryCopy(source, dest, copySubDirs: true))
                {
                    Console.WriteLine("[*] Copied directory " + source + " and all contents to " + dest);
                }
                return 0;
            }

            if (File.Exists(dest))
            {
                overwrite = true;
            }
            try
            {
                File.Copy(source, dest, overwrite: true);
                if (overwrite == true)
                {
                    Console.WriteLine("[*] Overwriting the destination file: " + dest);
                }
                Console.WriteLine("[*] File successfully copied from " + source + " to " + dest);
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Error: permission denied during copy operation");
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error: Unexpected exception during copy");
                Console.WriteLine(e);
            }
            return 0;
        }

        static int Ls(string[] args)
        {
            if (args.Length > 1)
            {
                Console.WriteLine("ls [path]");
                return 0;
            }
            else if (args.Length == 1 && (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help"))
            {
                Console.WriteLine("WinBinReplacements: ls [path]");
                return 0;
            }

            string dir = Directory.GetCurrentDirectory();
            string[] files = null;
            string[] subdirs = null;
            long biggestFileSize = 0;
            int sizeCharLength = 4; //Minimum size of "Size" column is 4 since must be at least as long as "Size "
            int biggestOwnerSize = 9; // "<Unknown>" is 9 chars
            if (args.Length == 1)
            {
                dir = args[0];
            }
            try
            {
                files = Directory.GetFiles(dir);
                subdirs = Directory.GetDirectories(dir);
                Console.WriteLine("\n  Directory listing of " + dir + "\n");
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("[!] Error: directory does not exist: " + dir);
                return 0;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Error: no permissions to read directory: " + dir);
                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error: unhandled exception listing directory: " + dir);
                Console.WriteLine(e);
                return 0;
            }

            string[] dirContents = files.Concat(subdirs).ToArray();
            Array.Sort(dirContents);
            if (dirContents == null)
            {
                Console.WriteLine("[*] The directory " + dir + " is empty!");
            }
            else
            {
                //Getting sizes of strings that need to be printed so the data can be formatted in a neat table
                foreach (string file in files)
                {
                    long fileSize = new FileInfo(file).Length;
                    if (fileSize > biggestFileSize)
                    {
                        biggestFileSize = fileSize;
                    }
                    if (sizeCharLength < biggestFileSize.ToString().Length)
                    {
                        sizeCharLength = biggestFileSize.ToString().Length;
                    }
                }
                foreach (string item in dirContents)
                {
                    try
                    {
                        if (File.GetAccessControl(item).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString().Length > biggestOwnerSize)
                        {
                            biggestOwnerSize = File.GetAccessControl(item).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString().Length;
                        }
                    }
                    catch { }

                }

                Console.WriteLine("Last Modify      Type     " + "Owner" + new string(' ', biggestOwnerSize - 5) + "   Size" + new string(' ', sizeCharLength - 4) + "   File/Dir Name");
                Console.WriteLine("==============   ======   " + new string('=', biggestOwnerSize) + "   " + new string('=', sizeCharLength) + "   =============");
                foreach (string item in dirContents)
                {
                    string relativepath = Path.GetFileName(item);
                    DateTime lastWriteDate = File.GetLastWriteTime(item);
                    string lastWrite = String.Format("{0:MM/dd/yy HH:mm}", lastWriteDate);
                    string owner;
                    try
                    {
                        owner = File.GetAccessControl(item).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString();
                    }
                    catch
                    {
                        owner = "<Unknown>";
                    }

                    if (files.Contains(item)) // item is a file
                    {
                        var fileSize = new FileInfo(item).Length;
                        Console.WriteLine(lastWrite + "   <File>   " + owner + new string(' ', biggestOwnerSize - owner.ToString().Length) + "   " + fileSize + new string(' ', sizeCharLength - fileSize.ToString().Length) + "   " + relativepath);
                    }
                    else // item is a directory
                    {
                        Console.WriteLine(lastWrite + "   <Dir>    " + owner + new string(' ', biggestOwnerSize - owner.ToString().Length) + "   " + new string('.', sizeCharLength) + "   " + relativepath);
                    }

                }
            }
            return 0;
        }

        static int Mkdir(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("mkdir <dir>[/subdir1/subdir2/...] [dir2] [dir3] ...");
                return 0;
            }

            foreach (string arg in args)
            {
                string fullPath = Path.GetFullPath(arg);
                try
                {
                    Directory.CreateDirectory(fullPath);
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Error: unauthorized to create directory " + fullPath);
                    continue;
                }
                catch (IOException)
                {
                    Console.WriteLine("[!] Error: IOException when trying to create directory " + fullPath);
                    continue;
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Error: unhandled exception when trying to create directory " + fullPath);
                    Console.Write(e);
                    continue;
                }
            }
            return 0;
        }

        static int Pwd(string[] args)
        {
            try
            {
                Console.WriteLine(Directory.GetCurrentDirectory());
                return 3;
            }
            catch
            {
                Console.WriteLine("[!] Failed to get current directory");
                return 0;
            }
        }

        static int Cd(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("cd <dir>");
                return 0;
            }
            try
            {
                Directory.SetCurrentDirectory(args[0]);
                Console.WriteLine(Directory.GetCurrentDirectory());
                return 3;
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception occured: Could not change dir to " + args[0]);
                Console.WriteLine(e);
                return 0;
            }
        }

        static int Rm(string[] args)
        {
            void setAttributesNormal(DirectoryInfo dir)
            {
                foreach (DirectoryInfo subDir in dir.GetDirectories())
                {
                    setAttributesNormal(subDir);
                }
                foreach (FileInfo file in dir.GetFiles())
                {
                    file.Attributes = FileAttributes.Normal;
                }
            }

            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("rm <item1> [item2] [item3] ...");
                return 0;
            }
            foreach (string arg in args)
            {
                string fileOrDir = Path.GetFullPath(arg);
                if (Directory.Exists(fileOrDir))
                {
                    try
                    {
                        DirectoryInfo dir = new DirectoryInfo(fileOrDir);
                        setAttributesNormal(dir);
                        Directory.Delete(fileOrDir, recursive: true);
                        Console.WriteLine("[*] Removed all child items and deleted directory: " + fileOrDir);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("[!] Error: access denied - could not delete directory: " + fileOrDir);
                    }
                    catch (IOException)
                    {
                        Console.WriteLine("[!] Error: IOException - could not delete directory: " + fileOrDir);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Error: Unexpected exception deleting directory: " + fileOrDir);
                        Console.WriteLine(e);
                    }

                }
                else if (File.Exists(fileOrDir))
                {
                    try
                    {
                        // prevent some files from resisting deletion
                        File.SetAttributes(fileOrDir, FileAttributes.Normal);
                        File.Delete(fileOrDir);
                        Console.WriteLine("[*] Deleted file: " + fileOrDir);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("[!] Error: access denied - could not delete file: " + fileOrDir);
                    }
                    catch (IOException)
                    {
                        Console.WriteLine("[!] Error: IOException - could not delete file: " + fileOrDir);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Error: Unexpected exception deleting file: " + fileOrDir);
                        Console.WriteLine(e);
                    }
                }
                else
                {
                    Console.WriteLine("[!] Error: file or directory does not exist: " + fileOrDir);
                }
            }
            return 0;
        }

        static int Upload(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("upload <local_path> <remote_path>");
                return 0;
            }
            // Format for Upload: <base64 blob of binary data to be uploaded> <path to upload to>
            byte[] data = Convert.FromBase64String(args[1]);
            string filepath = args[0];
            try
            {
                File.WriteAllBytes(filepath, data);
                Console.WriteLine("[+] Success: Wrote " + data.Length.ToString() + " bytes to: " + args[1]);
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("[!] Could not write file: " + filepath + " Required parent directory doesn't exist. Typo?");
            }
            catch (IOException)
            {
                Console.WriteLine("[!] Could not write file: " + filepath + " IOException. File locked?");
            }
            catch (SecurityException)
            {
                Console.WriteLine("[!] Could not write file: " + filepath + " SecurityException. No permissions to access file?");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Could not write file: " + filepath + " UnauthorizedAccessException. No permissions to access file?");
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Unhandled Exception when creating file: " + filepath);
                Console.Write(e);
            }
            return 0;
        }

        static int Download(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
            {
                Console.WriteLine("download <remote_file>");
                return 0;
            }
            string filepath = args[0];
            try
            {
                byte[] filecontent = File.ReadAllBytes(filepath);
                Console.WriteLine(Convert.ToBase64String(filecontent));
                return 1; // returnType 1 = download
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("[!] Could not read file: " + filepath + " File does not exist");
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("[!] Could not read file: " + filepath + " File does not exist");
            }
            catch (IOException)
            {
                Console.WriteLine("[!] Could not read file: " + filepath + " IOException. Maybe file is locked?");
            }
            catch (SecurityException)
            {
                Console.WriteLine("[!] Could not read file: " + filepath + " SecurityException. Do you have permission to read the file?");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Could not read file: " + filepath + " UnauthorizedAccessException. Do you have permission to read the file?");
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Unhandled Exception when creating file: " + filepath);
                Console.Write(e);
            }
            return 0;
        }
    }
}
