using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Microsoft.Win32;
using SecureTaskManager.Models;

namespace SecureTaskManager.Services
{
    public class StartupManager
    {
        public List<StartupInfo> GetAllStartupItems()
        {
            var items = new List<StartupInfo>();

            GetRegistryStartupItems(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Registry (HKLM)", items);
            GetRegistryStartupItems(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Registry (HKCU)", items);
            GetRegistryStartupItems(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Registry (HKLM Once)", items);
            GetRegistryStartupItems(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Registry (HKCU Once)", items);
            GetRegistryStartupItems(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Registry (HKLM x86)", items);

            GetStartupFolderItems(items);

            return items.OrderBy(i => i.Name).ToList();
        }

        private void GetRegistryStartupItems(RegistryKey root, string keyPath, string startupType, List<StartupInfo> items)
        {
            try
            {
                using (var key = root.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            try
                            {
                                var value = key.GetValue(valueName)?.ToString();
                                if (!string.IsNullOrEmpty(value))
                                {
                                    var path = ExtractPathFromCommand(value);
                                    var item = new StartupInfo
                                    {
                                        Name = valueName,
                                        Path = value,
                                        StartupType = startupType,
                                        IsEnabled = true,
                                        RegistryKey = $"{root.Name}\\{keyPath}",
                                        Publisher = GetPublisher(path),
                                        IsUnsigned = !IsDigitallySigned(path)
                                    };
                                    items.Add(item);
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            catch { }
        }

        private void GetStartupFolderItems(List<StartupInfo> items)
        {
            try
            {
                var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(startupFolder))
                {
                    foreach (var file in Directory.GetFiles(startupFolder, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        var item = new StartupInfo
                        {
                            Name = Path.GetFileNameWithoutExtension(file),
                            Path = file,
                            StartupType = "Startup Folder",
                            IsEnabled = true,
                            Publisher = GetPublisher(file),
                            IsUnsigned = !IsDigitallySigned(file)
                        };
                        items.Add(item);
                    }
                }
            }
            catch { }
        }

        private string ExtractPathFromCommand(string command)
        {
            if (string.IsNullOrEmpty(command))
                return "";

            command = command.Trim();
            if (command.StartsWith("\""))
            {
                int endQuote = command.IndexOf("\"", 1);
                if (endQuote > 0)
                    return command.Substring(1, endQuote - 1);
            }

            var parts = command.Split(' ');
            return parts[0];
        }

        private string GetPublisher(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return "";

            try
            {
                var cert = X509Certificate.CreateFromSignedFile(filePath);
                if (cert != null)
                {
                    var cert2 = new X509Certificate2(cert);
                    return cert2.Subject;
                }
            }
            catch { }
            return "";
        }

        private bool IsDigitallySigned(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return false;

            try
            {
                X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                if (cert == null)
                    return false;

                X509Certificate2 cert2 = new X509Certificate2(cert);
                cert.Dispose();

                if (cert2.NotAfter < DateTime.Now || cert2.NotBefore > DateTime.Now)
                {
                    cert2.Dispose();
                    return false;
                }

                bool isValid = false;
                try
                {
                    X509Chain chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
                    isValid = chain.Build(cert2);
                    chain.Reset();
                }
                catch
                {
                    isValid = true;
                }

                cert2.Dispose();
                return isValid;
            }
            catch
            {
                return false;
            }
        }

        public void DisableStartupItem(StartupInfo item)
        {
            if (item.StartupType.Contains("Registry"))
            {
                try
                {
                    var root = item.RegistryKey.StartsWith("HKEY_LOCAL_MACHINE") ? Registry.LocalMachine : Registry.CurrentUser;
                    var keyPath = item.RegistryKey.Substring(item.RegistryKey.IndexOf('\\') + 1);
                    
                    using (var key = root.OpenSubKey(keyPath, true))
                    {
                        if (key != null)
                        {
                            key.DeleteValue(item.Name, false);
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to disable startup item: {ex.Message}");
                }
            }
            else if (item.StartupType == "Startup Folder")
            {
                try
                {
                    if (File.Exists(item.Path))
                    {
                        File.Delete(item.Path);
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to delete startup file: {ex.Message}");
                }
            }
        }

        public void DeleteStartupItem(StartupInfo item)
        {
            DisableStartupItem(item);
        }
    }
}
