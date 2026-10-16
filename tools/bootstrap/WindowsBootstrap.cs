// Initial compiler boundary only. Product and normal build supervision live in Rust.
// Job list: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
// Limits: https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Mmmm.Bootstrap {
    public sealed class RunResult {
        public int? CommandExit;
        public bool Drained;
        public long ElapsedMilliseconds;
        public string[] SupervisorErrors;
        public uint MaximumPostLeaderProcesses;
        public bool OwnedTailTerminated;
    }

    public static class WindowsBoundary {
        private const uint CreateSuspended = 0x4;
        private const uint CreateNoWindow = 0x08000000;
        private const uint ExtendedStartupInfo = 0x00080000;
        private const uint StartupUseStdHandles = 0x100;
        private const uint JobKillOnClose = 0x2000;
        private const uint JobMemory = 0x200;
        private const uint JobActiveProcesses = 0x8;
        private const uint WaitObject0 = 0;
        private const uint WaitTimeout = 258;
        private const long NaturalDrainGraceMilliseconds = 2000;
        private static volatile bool cancelled;

        [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes {
            public uint Size; public IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] private struct StartupInfo {
            public uint Size; public string Reserved; public string Desktop; public string Title;
            public uint X; public uint Y; public uint XSize; public uint YSize;
            public uint XCountChars; public uint YCountChars; public uint FillAttribute;
            public uint Flags; public ushort ShowWindow; public ushort ReservedBytes;
            public IntPtr ReservedPointer; public IntPtr StdInput; public IntPtr StdOutput; public IntPtr StdError;
        }
        [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx {
            public StartupInfo Startup; public IntPtr Attributes;
        }
        [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo {
            public IntPtr Process; public IntPtr Thread; public uint ProcessId; public uint ThreadId;
        }
        [StructLayout(LayoutKind.Sequential)] private struct BasicLimit {
            public long ProcessTime; public long JobTime; public uint Flags;
            public UIntPtr MinWorkingSet; public UIntPtr MaxWorkingSet;
            public uint ActiveProcessLimit; public UIntPtr Affinity;
            public uint PriorityClass; public uint SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)] private struct IoCounters {
            public ulong ReadOperations; public ulong WriteOperations; public ulong OtherOperations;
            public ulong ReadBytes; public ulong WriteBytes; public ulong OtherBytes;
        }
        [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimit {
            public BasicLimit Basic; public IoCounters Io;
            public UIntPtr ProcessMemory; public UIntPtr JobMemory;
            public UIntPtr PeakProcessMemory; public UIntPtr PeakJobMemory;
        }
        [StructLayout(LayoutKind.Sequential)] private struct Accounting {
            public long UserTime; public long KernelTime; public long UserPeriod; public long KernelPeriod;
            public uint PageFaultCount; public uint TotalProcesses; public uint ActiveProcesses; public uint TerminatedProcesses;
        }

        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr CreateJobObjectW(IntPtr security, string name);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool SetInformationJobObject(IntPtr job, int kind, ref ExtendedLimit information, uint size);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool QueryInformationJobObject(IntPtr job, int kind, out Accounting information, uint size, IntPtr returned);
        [DllImport("kernel32.dll", EntryPoint="QueryInformationJobObject", SetLastError=true)] private static extern bool QueryJobProcessIds(IntPtr job, int kind, IntPtr information, uint size, IntPtr returned);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool inJob);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr bytes);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool CreateProcessW(string executable, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInfo process);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder path, ref uint size);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SecurityAttributes security, uint size);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool ReadFile(IntPtr file, byte[] buffer, uint requested, out uint received, IntPtr overlapped);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr CreateFileW(string name, uint access, uint sharing, ref SecurityAttributes security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint capacity, uint flags);

        private static Exception NativeError(string operation) {
            int code=Marshal.GetLastWin32Error();
            // The system message uses only the captured error code. Never append
            // executable arguments or environment values to native diagnostics.
            string systemMessage=new Win32Exception(code).Message;
            return new Win32Exception(code, Diagnostic(operation+"; win32="+code+"; message="+systemMessage));
        }
        private static string Diagnostic(string message) {
            if(string.IsNullOrWhiteSpace(message)) return "bootstrap supervisor failure without diagnostic text";
            StringBuilder bounded=new StringBuilder();
            foreach(char value in message) {
                if(bounded.Length>=512) break;
                bounded.Append(char.IsControl(value) ? ' ' : value);
            }
            return bounded.ToString();
        }
        private static string OwnedProcessNames(IntPtr job) {
            // The job's configured process limit is 32. Only IDs from this job
            // are inspected, and pinned handle membership is checked again.
            int capacity=32; int bytes=8+IntPtr.Size*capacity;
            IntPtr list=Marshal.AllocHGlobal(bytes);
            try {
                if(!QueryJobProcessIds(job,3,list,(uint)bytes,IntPtr.Zero)) return "unavailable(win32="+Marshal.GetLastWin32Error()+")";
                uint count=unchecked((uint)Marshal.ReadInt32(list,4));
                if(count>capacity) return "unavailable(job process list exceeded bound)";
                List<string> names=new List<string>();
                for(int i=0;i<count;i++) {
                    long raw=Marshal.ReadIntPtr(list,8+IntPtr.Size*i).ToInt64();
                    if(raw<=0 || raw>uint.MaxValue) { names.Add("invalid-job-pid"); continue; }
                    uint pid=(uint)raw; IntPtr process=OpenProcess(0x1000,false,pid);
                    if(process==IntPtr.Zero) { names.Add(pid+":unavailable"); continue; }
                    try {
                        bool member;
                        if(!IsProcessInJob(process,job,out member) || !member) { names.Add(pid+":no-longer-job-owned"); continue; }
                        StringBuilder image=new StringBuilder(32768); uint length=(uint)image.Capacity;
                        if(!QueryFullProcessImageNameW(process,0,image,ref length)) { names.Add(pid+":name-unavailable"); continue; }
                        string basename=Path.GetFileNameWithoutExtension(image.ToString());
                        StringBuilder safe=new StringBuilder();
                        foreach(char letter in basename) { if(safe.Length>=64) break; safe.Append(char.IsLetterOrDigit(letter)||letter=='-'||letter=='_'||letter=='.' ? letter : '_'); }
                        names.Add(pid+":"+safe);
                    } finally { Close(ref process); }
                }
                return string.Join(",",names);
            } finally { Marshal.FreeHGlobal(list); }
        }
        private static void Close(ref IntPtr handle) { if(handle != IntPtr.Zero && handle != new IntPtr(-1)) CloseHandle(handle); handle = IntPtr.Zero; }
        private static string Quote(string argument) {
            if(argument.IndexOf('\0') >= 0) throw new ArgumentException("NUL in process argument");
            StringBuilder value = new StringBuilder("\""); int slashes = 0;
            foreach(char c in argument) {
                if(c == '\\') { slashes++; continue; }
                if(c == '"') { value.Append('\\', slashes * 2 + 1); value.Append('"'); }
                else { value.Append('\\', slashes); value.Append(c); }
                slashes = 0;
            }
            value.Append('\\', slashes * 2); value.Append('"'); return value.ToString();
        }
        private static IntPtr OpenInput() {
            SecurityAttributes security = new SecurityAttributes { Size=(uint)Marshal.SizeOf<SecurityAttributes>(), InheritHandle=true };
            IntPtr result = CreateFileW("NUL", 0x80000000u, 1, ref security, 3, 0x80, IntPtr.Zero);
            if(result == new IntPtr(-1)) throw NativeError("create bootstrap standard handle");
            return result;
        }
        private static void OutputPipe(out IntPtr read, out IntPtr write) {
            SecurityAttributes security=new SecurityAttributes { Size=(uint)Marshal.SizeOf<SecurityAttributes>(), InheritHandle=true };
            if(!CreatePipe(out read, out write, ref security, 65536)) throw NativeError("create bootstrap output pipe");
            if(!SetHandleInformation(read, 1, 0)) throw NativeError("exclude output reader from inheritance");
        }
        private sealed class Capture {
            private readonly object gate=new object();
            private long retained; private long observed;
            private string failure;
            public string Failure { get { lock(gate) { return failure; } } }
            public void Pump(IntPtr read, string path) {
                try {
                    using(FileStream file=new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) {
                        byte[] buffer=new byte[65536]; uint received;
                        while(true) {
                            bool success=ReadFile(read, buffer, (uint)buffer.Length, out received, IntPtr.Zero);
                            if(!success) {
                                int error=Marshal.GetLastWin32Error();
                                if(error==109) break;
                                throw new Win32Exception(error, "read bootstrap output");
                            }
                            if(received==0) break;
                            int keep;
                            lock(gate) {
                                observed=checked(observed+received);
                                keep=(int)Math.Min(received, Math.Max(0, 128L*1024*1024-retained));
                                retained+=keep;
                                if(observed>128L*1024*1024 && failure==null) failure="bootstrap output budget exceeded";
                            }
                            // Timeout observation never waits for filesystem writes under this lock.
                            if(keep>0) file.Write(buffer,0,keep);
                        }
                        file.Flush(true);
                    }
                } catch(Exception exception) { lock(gate) { if(failure==null) failure="bootstrap output capture failed: "+exception.Message; } }
            }
        }

        public static string PhysicalDirectory(string path) {
            SecurityAttributes security = new SecurityAttributes { Size=(uint)Marshal.SizeOf<SecurityAttributes>() };
            IntPtr file = CreateFileW(path, 0, 7, ref security, 3, 0x02000000, IntPtr.Zero);
            if(file == new IntPtr(-1)) throw NativeError("open directory identity");
            try {
                StringBuilder resolved = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandleW(file, resolved, (uint)resolved.Capacity, 0);
                if(length == 0 || length >= resolved.Capacity) throw NativeError("resolve directory identity");
                string result = resolved.ToString();
                if(result.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) throw new IOException("Network roots are not supported by the bootstrap");
                if(result.StartsWith("\\\\?\\", StringComparison.Ordinal)) result = result.Substring(4);
                return result.TrimEnd('\\');
            } finally { Close(ref file); }
        }

        // The callback measures only the exact owned catalog; it returns null or a bounded diagnostic.
        public static RunResult Run(string executable, string[] arguments, string directory,
            string stdout, string stderr, int timeoutSeconds, Func<string> observeBudget) {
            return Run(executable, arguments, directory, stdout, stderr, timeoutSeconds, observeBudget, false);
        }

        // Only an explicitly selected compiler build may clean up its whole owned
        // Job after the leader exits. Control commands keep the strict overload.
        public static RunResult Run(string executable, string[] arguments, string directory,
            string stdout, string stderr, int timeoutSeconds, Func<string> observeBudget,
            bool terminateOwnedBuildTail) {
            if(timeoutSeconds < 1 || timeoutSeconds > 3600) throw new ArgumentOutOfRangeException("timeoutSeconds");
            IntPtr job=IntPtr.Zero, attributes=IntPtr.Zero, handleValues=IntPtr.Zero, jobValues=IntPtr.Zero;
            IntPtr input=IntPtr.Zero, output=IntPtr.Zero, error=IntPtr.Zero, outputRead=IntPtr.Zero, errorRead=IntPtr.Zero;
            ProcessInfo process = new ProcessInfo(); bool initialized=false; bool created=false;
            List<string> errors = new List<string>(); int? exit=null; bool drained=false;
            long? leaderExitedAt=null; int emptyObservations=0;
            uint maximumPostLeaderProcesses=0;
            long? tailCleanupStartedAt=null; bool ownedTailTerminated=false;
            Stopwatch elapsed = Stopwatch.StartNew(); Stopwatch lastMeasurement = Stopwatch.StartNew();
            Capture capture=new Capture(); Thread outputPump=null, errorPump=null; Timer watchdog=null;
            object timerGate=new object(); bool disposed=false; string watchdogFailure=null;
            ConsoleCancelEventHandler cancel = delegate(object sender, ConsoleCancelEventArgs args) { cancelled=true; args.Cancel=true; };
            cancelled=false; Console.CancelKeyPress += cancel;
            try {
                job=CreateJobObjectW(IntPtr.Zero, null); if(job==IntPtr.Zero) throw NativeError("create bootstrap job");
                ExtendedLimit limits = new ExtendedLimit();
                limits.Basic.Flags=JobKillOnClose|JobMemory|JobActiveProcesses;
                limits.Basic.ActiveProcessLimit=32; limits.JobMemory=new UIntPtr(2UL * 1024 * 1024 * 1024);
                if(!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimit>())) throw NativeError("set bootstrap job limits");
                input=OpenInput(); OutputPipe(out outputRead, out output); OutputPipe(out errorRead, out error);
                IntPtr bytes=IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref bytes);
                if(bytes==IntPtr.Zero) throw NativeError("size bootstrap attributes");
                attributes=Marshal.AllocHGlobal(bytes);
                if(!InitializeProcThreadAttributeList(attributes, 2, 0, ref bytes)) throw NativeError("initialize bootstrap attributes");
                initialized=true;
                handleValues=Marshal.AllocHGlobal(IntPtr.Size*3); jobValues=Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(handleValues, 0, input); Marshal.WriteIntPtr(handleValues, IntPtr.Size, output);
                Marshal.WriteIntPtr(handleValues, IntPtr.Size*2, error); Marshal.WriteIntPtr(jobValues, job);
                if(!UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handleValues, new IntPtr(IntPtr.Size*3), IntPtr.Zero, IntPtr.Zero)) throw NativeError("set standard handle list");
                if(!UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x2000D), jobValues, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) throw NativeError("set atomic bootstrap job list (Windows 10 required)");
                StartupInfoEx startup=new StartupInfoEx(); startup.Startup.Size=(uint)Marshal.SizeOf<StartupInfoEx>();
                startup.Startup.Flags=StartupUseStdHandles; startup.Startup.StdInput=input;
                startup.Startup.StdOutput=output; startup.Startup.StdError=error; startup.Attributes=attributes;
                StringBuilder command=new StringBuilder(Quote(executable));
                foreach(string argument in arguments) command.Append(' ').Append(Quote(argument));
                if(command.Length >= 32767) throw new ArgumentException("Process command exceeds Win32 limit");
                if(!CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                    CreateSuspended|CreateNoWindow|ExtendedStartupInfo, IntPtr.Zero, directory, ref startup, out process)) throw NativeError("create atomically owned bootstrap process");
                created=true; bool inJob;
                if(!IsProcessInJob(process.Process, job, out inJob) || !inJob) throw NativeError("verify bootstrap job membership");
                // Only the child owns pipe writers after creation. The job is never inherited.
                Close(ref output); Close(ref error);
                outputPump=new Thread(delegate() { capture.Pump(outputRead, stdout); }); outputPump.IsBackground=true; outputPump.Start();
                errorPump=new Thread(delegate() { capture.Pump(errorRead, stderr); }); errorPump.IsBackground=true; errorPump.Start();
                watchdog=new Timer(delegate(object state) {
                    lock(timerGate) {
                        if(disposed || watchdogFailure!=null) return;
                        string reason=cancelled ? "cancelled" : elapsed.Elapsed.TotalSeconds>=timeoutSeconds ? "timeout" : capture.Failure;
                        if(reason!=null) {
                            watchdogFailure=reason;
                            if(!TerminateJobObject(job,124)) watchdogFailure += "; independent job termination failed: "+Marshal.GetLastWin32Error();
                        }
                    }
                }, null, 0, 100);
                if(ResumeThread(process.Thread)==uint.MaxValue) throw NativeError("resume bootstrap process");
                Close(ref process.Thread);
                while(true) {
                    uint wait=WaitForSingleObject(process.Process, 100);
                    if(wait!=WaitObject0 && wait!=WaitTimeout) throw NativeError("observe bootstrap leader");
                    if(wait==WaitObject0 && !exit.HasValue) {
                        uint code; if(!GetExitCodeProcess(process.Process, out code)) throw NativeError("read bootstrap command exit");
                        exit=unchecked((int)code);
                        leaderExitedAt=elapsed.ElapsedMilliseconds;
                    }
                    Accounting accounting;
                    if(!QueryInformationJobObject(job, 1, out accounting, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero)) throw NativeError("observe bootstrap physical drain");
                    if(exit.HasValue) maximumPostLeaderProcesses=Math.Max(maximumPostLeaderProcesses,accounting.ActiveProcesses);
                    if(accounting.ActiveProcesses==0) {
                        if(!exit.HasValue) {
                            if(WaitForSingleObject(process.Process,1000)!=WaitObject0) throw NativeError("drained job leader did not signal");
                            uint code; if(!GetExitCodeProcess(process.Process,out code)) throw NativeError("capture drained command exit");
                            exit=unchecked((int)code);
                            leaderExitedAt=elapsed.ElapsedMilliseconds;
                        }
                        emptyObservations++;
                    } else { emptyObservations=0; }
                    string failure=null;
                    lock(timerGate) { failure=watchdogFailure; }
                    if(failure!=null) { }
                    else if(cancelled) failure="cancelled";
                    else if(elapsed.Elapsed.TotalSeconds >= timeoutSeconds) failure="timeout";
                    else if(capture.Failure!=null) failure=capture.Failure;
                    else if(lastMeasurement.ElapsedMilliseconds >= 5000) {
                        failure=observeBudget();
                        // PowerShell Func<string> marshals a successful $null as String.Empty.
                        if(string.IsNullOrEmpty(failure)) failure=null;
                        lastMeasurement.Restart();
                    }
                    // A catalog observation may cross a deadline. Also inspect
                    // synchronous conditions before accepting an empty Job, so
                    // a delayed Timer callback cannot turn a timeout into success.
                    if(failure==null) {
                        lock(timerGate) { failure=watchdogFailure; }
                        if(failure==null && cancelled) failure="cancelled";
                        if(failure==null && elapsed.Elapsed.TotalSeconds>=timeoutSeconds) failure="timeout";
                        if(failure==null && capture.Failure!=null) failure=capture.Failure;
                        if(failure==null && tailCleanupStartedAt.HasValue &&
                            elapsed.ElapsedMilliseconds-tailCleanupStartedAt.Value>=30000)
                            failure="owned bootstrap build tail drain deadline exceeded; ownership preserved";
                    }
                    if(failure==null && exit.HasValue && accounting.ActiveProcesses!=0 && leaderExitedAt.HasValue &&
                        elapsed.ElapsedMilliseconds-leaderExitedAt.Value>=NaturalDrainGraceMilliseconds) {
                        if(!terminateOwnedBuildTail) {
                            failure="command exited with live owned children after 2000 ms natural drain grace; active="+
                                accounting.ActiveProcesses+"; job-owned="+OwnedProcessNames(job);
                        } else if(!tailCleanupStartedAt.HasValue) {
                            // The command has already exited, so preserve its original
                            // exit code. No process names, globals or breakaway policy
                            // can weaken this whole-Job ownership boundary.
                            if(!TerminateJobObject(job,124)) throw NativeError("terminate owned bootstrap build tail");
                            ownedTailTerminated=true;
                            tailCleanupStartedAt=elapsed.ElapsedMilliseconds;
                            emptyObservations=0;
                        }
                    }
                    if(failure!=null) {
                        errors.Add(Diagnostic(failure));
                        if(!TerminateJobObject(job, 124)) throw NativeError("terminate bootstrap job");
                        Stopwatch drain=Stopwatch.StartNew();
                        while(drain.ElapsedMilliseconds < 30000) {
                            if(!QueryInformationJobObject(job, 1, out accounting, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero)) throw NativeError("confirm bootstrap termination drain");
                            if(accounting.ActiveProcesses==0) { drained=true; break; }
                            Thread.Sleep(50);
                        }
                        if(!drained) errors.Add("bootstrap drain deadline exceeded; ownership preserved");
                        if(WaitForSingleObject(process.Process, 0)==WaitObject0 && !exit.HasValue) {
                            uint code; if(GetExitCodeProcess(process.Process, out code)) exit=unchecked((int)code);
                        }
                        break;
                    }
                    if(emptyObservations>=2) { drained=true; break; }
                    // A signaled leader handle no longer provides a timed wait.
                    // Keep grace/accounting observations finite and separated.
                    if(exit.HasValue) Thread.Sleep(100);
                }
            } catch(Exception exception) {
                errors.Add(Diagnostic(exception.Message));
                if(job!=IntPtr.Zero) {
                    if(!TerminateJobObject(job, 125)) errors.Add("terminate after supervisor failure: " + Marshal.GetLastWin32Error());
                    Stopwatch drain=Stopwatch.StartNew();
                    while(drain.ElapsedMilliseconds < 30000) {
                        Accounting accounting;
                        if(!QueryInformationJobObject(job, 1, out accounting, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero)) { errors.Add("drain query failed: " + Marshal.GetLastWin32Error()); break; }
                        if(accounting.ActiveProcesses==0) { drained=true; break; }
                        Thread.Sleep(50);
                    }
                }
                if(!created && job==IntPtr.Zero) drained=true;
            } finally {
                Console.CancelKeyPress -= cancel;
                if(watchdog!=null) watchdog.Dispose();
                lock(timerGate) {
                    disposed=true;
                    if(watchdogFailure!=null && !errors.Contains(watchdogFailure)) errors.Add(watchdogFailure);
                    Close(ref job);
                }
                Close(ref output); Close(ref error);
                if(outputPump!=null && !outputPump.Join(30000)) { errors.Add("stdout capture did not drain; ownership preserved"); drained=false; }
                if(errorPump!=null && !errorPump.Join(30000)) { errors.Add("stderr capture did not drain; ownership preserved"); drained=false; }
                if(capture.Failure!=null && !errors.Contains(capture.Failure)) errors.Add(capture.Failure);
                // Do not close/recycle a read handle beneath a live pump thread.
                if(outputPump==null || !outputPump.IsAlive) Close(ref outputRead);
                if(errorPump==null || !errorPump.IsAlive) Close(ref errorRead);
                if(!exit.HasValue && process.Process!=IntPtr.Zero && WaitForSingleObject(process.Process,0)==WaitObject0) {
                    uint code; if(GetExitCodeProcess(process.Process,out code)) exit=unchecked((int)code);
                }
                Close(ref process.Thread); Close(ref process.Process);
                Close(ref input); Close(ref output); Close(ref error);
                if(initialized) DeleteProcThreadAttributeList(attributes);
                if(attributes!=IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                if(handleValues!=IntPtr.Zero) Marshal.FreeHGlobal(handleValues);
                if(jobValues!=IntPtr.Zero) Marshal.FreeHGlobal(jobValues);
            }
            return new RunResult { CommandExit=exit, Drained=drained, ElapsedMilliseconds=elapsed.ElapsedMilliseconds, SupervisorErrors=errors.ToArray(), MaximumPostLeaderProcesses=maximumPostLeaderProcesses, OwnedTailTerminated=ownedTailTerminated };
        }
    }
}
