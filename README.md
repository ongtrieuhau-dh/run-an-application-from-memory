# Run an application from memory 
## [wojciechkulik.pl/csharp/run-an-application-from-memory](https://wojciechkulik.pl/csharp/run-an-application-from-memory)
## [Sample-Projects](https://github.com/wojciech-kulik/Sample-Projects/tree/master/Windows%20Desktop/NET_MemoryAppLoader)
## What for?
There are many reasons why running an application from memory may be useful. For example your machine might have white-listed applications or you might want to gain some security by deploying encrypted software, which can be run only by a special launcher.
## Console and Windows Forms Applications
There is a very easy way to launch an exe file with Console Application or Windows Forms Application (doesn’t work with WPF).  The only thing we need to do is to find an entry point (using reflection + Assembly class) and invoke it.
```
using System.Reflection;
using System.Threading;
 
namespace MemoryAppLoader
{
    public static class MemoryUtils
    {
        public static Thread RunFromMemory(byte[] bytes)
        {
            var thread = new Thread(new ThreadStart(() =>
            {
                var assembly = Assembly.Load(bytes);
                MethodInfo method = assembly.EntryPoint;
                if (method != null)
                {
                    method.Invoke(null, null);
                }
            }));
 
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
 
            return thread;
        }
    }
}
 
// USAGE: MemoryUtils.RunFromMemory(File.ReadAllBytes("YOUR_EXE_FILE")).Join();
```
## DLLs
You have to copy all of your DLLs to the directory with the launcher, so that the running process can access them. In case you would like to have an application in a single file, you can always pack all together and unpack from the launcher.

It is also possible to prepare an application with embedded libraries, for more information read [this article](http://wojciechkulik.pl/c-sharp/embedded-class-libraries-dll).
## Serialization
If you serialize objects through a BinaryFormatter, you won’t be able to deserialize them. To avoid this issue you need to move all your own serializable classes to another Class Library project.

In case of some unexpected errors, reflection calls may be worth to check first. I think those places are quite risky.
## Sample project
[.NET MemoryAppLoader](https://github.com/wojciech-kulik/Sample-Projects/tree/master/Windows%20Desktop/NET_MemoryAppLoader)
## Win32 applications
For Win32 applications it’s a little bit more complicated and there are some limitations:

Your DLLs might not work, because the application will be injected to C:\Windows\Microsoft.NET\ Framework\v2.0.50727\vbc.exe, so you’d have to copy libraries there.
Launcher and the application has to be built for x86.
Launcher has to be built with “allow unsafe code” option (Project properties -> Build).
```
using System;
using System.Runtime.InteropServices;
 
/* 
 * Title: CMemoryExecute.cs
 * Description: Runs an EXE in memory using native WinAPI. Very optimized and tiny.
 * 
 * Developed by: affixiate 
 * Release date: December 10, 2010
 * Released on: http://opensc.ws
 * Credits:
 *          MSDN (http://msdn.microsoft.com)
 *          NtInternals (http://undocumented.ntinternals.net)
 *          Pinvoke (http://pinvoke.net)
 *          
 * Comments: If you use this code, I require you to give me credits. Don't be a ripper! ;]
 */
 
// ReSharper disable InconsistentNaming
public static unsafe class CMemoryExecute
{
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
 
    /// <summary>
    /// Runs an EXE (which is loaded in a byte array) in memory.
    /// </summary>
    /// <param name="exeBuffer">The EXE buffer.</param>
    /// <param name="hostProcess">Full path of the host process to run the buffer in.</param>
    /// <param name="optionalArguments">Optional command line arguments.</param>
    /// <returns></returns>
    public static bool Run(byte[] exeBuffer, string hostProcess, string optionalArguments = "")
    {
        // STARTUPINFO
        STARTUPINFO StartupInfo = new STARTUPINFO();
        StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        StartupInfo.wShowWindow = SW_HIDE;
 
        var IMAGE_SECTION_HEADER = new byte[0x28]; // pish
        var IMAGE_NT_HEADERS = new byte[0xf8]; // pinh
        var IMAGE_DOS_HEADER = new byte[0x40]; // pidh
        var PROCESS_INFO = new int[0x4]; // pi
        var CONTEXT = new byte[0x2cc]; // ctx
 
        byte* pish;
        fixed (byte* p = &IMAGE_SECTION_HEADER[0])
            pish = p;
 
        byte* pinh;
        fixed (byte* p = &IMAGE_NT_HEADERS[0])
            pinh = p;
 
        byte* pidh;
        fixed (byte* p = &IMAGE_DOS_HEADER[0])
            pidh = p;
 
        byte* ctx;
        fixed (byte* p = &CONTEXT[0])
            ctx = p;
 
        // Set the flag.
        *(uint*)(ctx + 0x0 /* ContextFlags */) = CONTEXT_FULL;
 
        // Get the DOS header of the EXE.
        Buffer.BlockCopy(exeBuffer, 0, IMAGE_DOS_HEADER, 0, IMAGE_DOS_HEADER.Length);
 
        /* Sanity check:  See if we have MZ header. */
        if (*(ushort*)(pidh + 0x0 /* e_magic */) != IMAGE_DOS_SIGNATURE)
            return false;
 
        var e_lfanew = *(int*)(pidh + 0x3c);
 
        // Get the NT header of the EXE.
        Buffer.BlockCopy(exeBuffer, e_lfanew, IMAGE_NT_HEADERS, 0, IMAGE_NT_HEADERS.Length);
 
        /* Sanity check: See if we have PE00 header. */
        if (*(uint*)(pinh + 0x0 /* Signature */) != IMAGE_NT_SIGNATURE)
            return false;
 
        // Run with parameters if necessary.
        if (!string.IsNullOrEmpty(optionalArguments))
            hostProcess += " " + optionalArguments;
 
        if (!CreateProcess(null, hostProcess, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref StartupInfo, PROCESS_INFO))
            return false;
 
        var ImageBase = new IntPtr(*(int*)(pinh + 0x34));
        NtUnmapViewOfSection((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase);
        if (VirtualAllocEx((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase, *(uint*)(pinh + 0x50 /* SizeOfImage */), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == IntPtr.Zero)
            return false;
 
        fixed (byte* p = &exeBuffer[0])
            NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase, (IntPtr)p, *(uint*)(pinh + 84 /* SizeOfHeaders */), IntPtr.Zero);
 
        for (ushort i = 0; i < *(ushort*)(pinh + 0x6 /* NumberOfSections */); i++)
        {
            Buffer.BlockCopy(exeBuffer, e_lfanew + IMAGE_NT_HEADERS.Length + (IMAGE_SECTION_HEADER.Length * i), IMAGE_SECTION_HEADER, 0, IMAGE_SECTION_HEADER.Length);
            fixed (byte* p = &exeBuffer[*(uint*)(pish + 0x14 /* PointerToRawData */)])
                NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, (IntPtr)((int)ImageBase + *(uint*)(pish + 0xc /* VirtualAddress */)), (IntPtr)p, *(uint*)(pish + 0x10 /* SizeOfRawData */), IntPtr.Zero);
        }
 
        NtGetContextThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, (IntPtr)ctx);
        NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, (IntPtr)(*(uint*)(ctx + 0xAC /* ecx */)), ImageBase, 0x4, IntPtr.Zero);
        *(uint*)(ctx + 0xB0 /* eax */) = (uint)ImageBase + *(uint*)(pinh + 0x28 /* AddressOfEntryPoint */);
        NtSetContextThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, (IntPtr)ctx);
        NtResumeThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, IntPtr.Zero);
        
        return true;
    }
 
    #region WinNT Definitions
 
    private const uint CONTEXT_FULL = 0x10007;
    private const int CREATE_SUSPENDED = 0x4;
    private const int MEM_COMMIT = 0x1000;
    private const int MEM_RESERVE = 0x2000;
    private const int PAGE_EXECUTE_READWRITE = 0x40;
    private const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
    private const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00
 
    private static short SW_SHOW = 5;
    private static short SW_HIDE = 0;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint STARTF_USESHOWWINDOW = 0x00000001;
 
 
    #region WinAPI
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, 
          IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, 
          uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, 
          ref STARTUPINFO lpStartupInfo, int[] lpProcessInfo);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
 
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);
 
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten);
 
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtGetContextThread(IntPtr hThread, IntPtr lpContext);
 
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetContextThread(IntPtr hThread, IntPtr lpContext);
 
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern uint NtResumeThread(IntPtr hThread, IntPtr SuspendCount);
    #endregion
 
    #endregion
}
 
// USAGE : CMemoryExecute.Run(File.ReadAllBytes("SampleApp.exe"), 
//                            @"C:\Windows\Microsoft.NET\Framework\v2.0.50727\vbc.exe");
```
## Sample project
[WIN32 MemoryAppLoader](https://github.com/wojciech-kulik/Sample-Projects/tree/master/Windows%20Desktop/WIN32_MemoryAppLoader)
## Summary
In some special cases this might be useful, but be aware it may become tricky with more advanced applications. Running an executable from memory isn’t secure either. Someone could dump memory and extract the app. However, it’s good to know some possibilities :-).
