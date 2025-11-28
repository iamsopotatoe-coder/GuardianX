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
        private MalwareSignatureDetector _md = new MalwareSignatureDetector();

        public List<StartupInfo> GetAllStartupItems()
        {
            var l = new List<StartupInfo>();

            _g(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Registry (HKLM)", l);
            _g(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Registry (HKCU)", l);
            _g(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Registry (HKLM Once)", l);
            _g(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Registry (HKCU Once)", l);
            _g(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Registry (HKLM x86)", l);

            _f(l);
            _t(l);
            _s(l);
            _ls(l);

            return l.OrderBy(i => i.Name).ToList();
        }

        private void _t(List<StartupInfo> l)
        {
            try
            {
                string d = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
                if (Directory.Exists(d))
                {
                    foreach (var f in Directory.GetFiles(d, "*", SearchOption.AllDirectories))
                    {
                        try
                        {
                            string c = File.ReadAllText(f);
                            if (c.Contains("<Command>"))
                            {
                                int s = c.IndexOf("<Command>") + 9;
                                int e = c.IndexOf("</Command>", s);
                                if (e > s)
                                {
                                    string x = c.Substring(s, e - s);
                                    var ms = _md.AnalyzeFile(x);
                                    l.Add(new StartupInfo
                                    {
                                        Name = Path.GetFileName(f),
                                        Path = x,
                                        StartupType = "Scheduled Task",
                                        IsEnabled = true,
                                        Publisher = _p(x),
                                        IsUnsigned = !_d(x),
                                        IsMalicious = ms.IsMalware,
                                        RiskLevel = ms.ThreatLevel
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private void _s(List<StartupInfo> l)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                {
                    if (k != null)
                    {
                        foreach (var n in k.GetSubKeyNames())
                        {
                            using (var sk = k.OpenSubKey(n))
                            {
                                var sm = sk?.GetValue("Start");
                                var ip = sk?.GetValue("ImagePath")?.ToString();

                                if (sm != null && (int)sm == 2 && !string.IsNullOrEmpty(ip))
                                {
                                    string p = _e(ip);
                                    var ms = _md.AnalyzeFile(p);
                                    l.Add(new StartupInfo
                                    {
                                        Name = n,
                                        Path = p,
                                        StartupType = "Service",
                                        IsEnabled = true,
                                        Publisher = _p(p),
                                        IsUnsigned = !_d(p),
                                        IsMalicious = ms.IsMalware,
                                        RiskLevel = ms.ThreatLevel
                                    });
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private void _ls(List<StartupInfo> l)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Environment"))
                {
                    var s = k?.GetValue("UserInitMprLogonScript")?.ToString();
                    if (!string.IsNullOrEmpty(s))
                    {
                        var ms = _md.AnalyzeFile(s);
                        l.Add(new StartupInfo
                        {
                            Name = "Logon Script",
                            Path = s,
                            StartupType = "Logon Script",
                            IsEnabled = true,
                            Publisher = _p(s),
                            IsUnsigned = !_d(s),
                            IsMalicious = ms.IsMalware,
                            RiskLevel = ms.ThreatLevel
                        });
                    }
                }
            }
            catch { }
        }

        private void _g(RegistryKey r, string kp, string st, List<StartupInfo> l)
        {
            try
            {
                using (var k = r.OpenSubKey(kp))
                {
                    if (k != null)
                    {
                        foreach (var vn in k.GetValueNames())
                        {
                            try
                            {
                                var v = k.GetValue(vn)?.ToString();
                                if (!string.IsNullOrEmpty(v))
                                {
                                    var p = _e(v);
                                    var ms = _md.AnalyzeFile(p);
                                    var i = new StartupInfo
                                    {
                                        Name = vn,
                                        Path = v,
                                        StartupType = st,
                                        IsEnabled = true,
                                        RegistryKey = $"{r.Name}\\{kp}",
                                        Publisher = _p(p),
                                        IsUnsigned = !_d(p),
                                        IsMalicious = ms.IsMalware,
                                        RiskLevel = ms.ThreatLevel
                                    };
                                    l.Add(i);
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            catch { }
        }

        private void _f(List<StartupInfo> l)
        {
            try
            {
                var sf = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(sf))
                {
                    foreach (var f in Directory.GetFiles(sf, "*.*", SearchOption.TopDirectoryOnly))
                    {
                        var ms = _md.AnalyzeFile(f);
                        var i = new StartupInfo
                        {
                            Name = Path.GetFileNameWithoutExtension(f),
                            Path = f,
                            StartupType = "Startup Folder",
                            IsEnabled = true,
                            Publisher = _p(f),
                            IsUnsigned = !_d(f),
                            IsMalicious = ms.IsMalware,
                            RiskLevel = ms.ThreatLevel
                        };
                        l.Add(i);
                    }
                }
            }
            catch { }
        }

        private string _e(string c)
        {
            if (string.IsNullOrEmpty(c))
                return "";

            c = c.Trim();
            if (c.StartsWith("\""))
            {
                int eq = c.IndexOf("\"", 1);
                if (eq > 0)
                    return c.Substring(1, eq - 1);
            }

            var p = c.Split(' ');
            return p[0];
        }

        private string _p(string fp)
        {
            if (string.IsNullOrEmpty(fp) || !File.Exists(fp))
                return "";

            try
            {
                var c = X509Certificate.CreateFromSignedFile(fp);
                if (c != null)
                {
                    var c2 = new X509Certificate2(c);
                    return c2.Subject;
                }
            }
            catch { }
            return "";
        }

        private bool _d(string fp)
        {
            if (string.IsNullOrEmpty(fp) || !File.Exists(fp))
                return false;

            try
            {
                X509Certificate c = X509Certificate.CreateFromSignedFile(fp);
                if (c == null)
                    return false;

                X509Certificate2 c2 = new X509Certificate2(c);
                c.Dispose();

                if (c2.NotAfter < DateTime.Now || c2.NotBefore > DateTime.Now)
                {
                    c2.Dispose();
                    return false;
                }

                bool v = false;
                try
                {
                    X509Chain ch = new X509Chain();
                    ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    ch.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
                    v = ch.Build(c2);
                    ch.Reset();
                }
                catch
                {
                    v = true;
                }

                c2.Dispose();
                return v;
            }
            catch
            {
                return false;
            }
        }

        public void DisableStartupItem(StartupInfo i)
        {
            if (i.StartupType.Contains("Registry"))
            {
                try
                {
                    var r = i.RegistryKey.StartsWith("HKEY_LOCAL_MACHINE") ? Registry.LocalMachine : Registry.CurrentUser;
                    var kp = i.RegistryKey.Substring(i.RegistryKey.IndexOf('\\') + 1);

                    using (var k = r.OpenSubKey(kp, true))
                    {
                        if (k != null)
                        {
                            k.DeleteValue(i.Name, false);
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to disable startup item: {ex.Message}");
                }
            }
            else if (i.StartupType == "Startup Folder")
            {
                try
                {
                    if (File.Exists(i.Path))
                    {
                        File.Delete(i.Path);
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to delete startup file: {ex.Message}");
                }
            }
        }

        public void DeleteStartupItem(StartupInfo i)
        {
            DisableStartupItem(i);
        }
    }
}
