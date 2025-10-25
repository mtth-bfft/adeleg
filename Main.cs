using System;
using System.Net;
using System.Windows.Forms;

namespace adeleg
{
    using adeleg.engine.connector;
    using engine;
    using gui;
    using System.Collections.Generic;
    using System.DirectoryServices.Protocols;
    using System.IO;
    using System.Text.Encodings.Web;
    using System.Text.Json;

    internal static class Starter
    {
        static void ShowUsage()
        {
            Console.WriteLine("");
            Console.WriteLine("Usage: adeleg.exe (without options to start a GUI)");
            Console.WriteLine("");
            Console.WriteLine("       adeleg.exe ldap [--server|-s <server>] (to override the default DC locator)");
            Console.WriteLine("                       [--username|-u <username>] (to not use the default Windows SSO)");
            Console.WriteLine("                       [--domain|-d <domain>] (user's domain name, when using -u)");
            Console.WriteLine("                       [--password|-p <password>] (to not prompt for a password, when using -u)");
            Console.WriteLine("");
            Console.WriteLine("       adeleg.exe oradad <path_to_directory>");
            Console.WriteLine("");
        }

        static List<Result> LoadTemplate(string filePath)
        {
            JsonSerializerOptions options = new JsonSerializerOptions();
            //options.Converters.Add(new ResultSerializer());
            options.Converters.Add(new ResultTrusteeSerializer());

            using (StreamReader r = new StreamReader(filePath))
            {
                try
                {
                    return JsonSerializer.Deserialize<List<Result>>(r.BaseStream, options);
                }
                catch (JsonException e)
                {
                    MessageBox.Show($"Invalid JSON in template file {filePath} : {e.Message}", "Invalid template file", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return new List<Result>();
                }
            }
        }

        static List<Result> LoadTemplates(string dirPath)
        {
            Console.WriteLine($" [.] Loading templates from {dirPath}");
            DirectoryInfo dir = new DirectoryInfo(dirPath);
            List<Result> templates = new List<Result>();
            if (dir.Exists)
            {
                foreach (FileInfo file in dir.GetFiles("*.json"))
                {
                    templates.AddRange(LoadTemplate(file.FullName));
                }
            }
            return templates;
        }

        static List<Result> LoadTemplates()
        {
            string exePath = System.Reflection.Assembly.GetEntryAssembly().Location;
            string exeDir = Path.GetDirectoryName(exePath);
            string mainTemplatesDir = Path.Combine(exeDir, "templates");
            string userTemplatesDir = Environment.ExpandEnvironmentVariables("%USERPROFILE%\\adeleg-templates");

            List<Result> templates = new List<Result>();
            templates.AddRange(LoadTemplates(mainTemplatesDir));
            templates.AddRange(LoadTemplates(userTemplatesDir));
            return templates;
        }

        [STAThread]
        static int Main(string[] args)
        {
            List<Result> templates = LoadTemplates();

            if (args.Length > 0)
            {
#if !DEBUG
                try
                {
#endif
                    return RunCLI(args, templates);
#if !DEBUG
                }
                catch (Exception exc)
                {
                    return FailWithError(exc.Message);
                }
#endif
            }
            else
            {
                return RunGUI(templates);
            }
        }

        static int RunCLI(string[] args, List<Result> templates)
        {
            List<IConnector> dataSources = new List<IConnector>();
            List<Result> results = new List<Result>();
            bool generalize = false;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--help" || args[i] == "-h" || args[i] == "-?")
                {
                    ShowUsage();
                    return 1;
                }
                else if (args[i] == "--generalize")
                {
                    generalize = true;
                }
                else if (args[i] == "ldap")
                {
                    int j;
                    string server = null;
                    ushort port = 389;
                    NetworkCredential creds = null;
                    string username = null;
                    string domain = null;
                    string password = null;

                    for (j = i+1; j < args.Length; j++)
                    {
                        if (args[j] == "--server" || args[j] == "-s")
                        {
                            if (j + 1 >= args.Length)
                                return FailWithError("server DNS hostname or IP address required after --server");
                            server = args[++j];
                        }
                        else if (args[j] == "--port")
                        {
                            if (j + 1 >= args.Length)
                                return FailWithError("TCP port required after --port");
                            port = ushort.Parse(args[++j]);
                        }
                        else if (args[j] == "--username" || args[j] == "-u")
                        {
                            if (j + 1 >= args.Length)
                                return FailWithError("username required after --username");
                            username = args[++j];
                        }
                        else if (args[j] == "--domain" || args[j] == "-d")
                        {
                            if (j + 1 >= args.Length)
                                return FailWithError("user's domain name required after --domain");
                            domain = args[++j];
                        }
                        else if (args[j] == "--password" || args[j] == "-p")
                        {
                            if (j + 1 >= args.Length)
                                return FailWithError("user's password required after --password");
                            password = args[++j];
                        }
                        else
                        {
                            break;
                        }
                    }
                    i = j - 1;

                    if (server == null)
                    {
                        server = LdapLiveConnector.AutolocateDomainController();
                        if (server == null)
                        {
                            return FailWithError("unable to automatically locate a domain controller, please specify --server manually");
                        }
                    }
                    if (username != null)
                    {
                        if (domain == null)
                        {
                            domain = ".";
                        }
                        if (password == null || password == "*")
                        {
                            password = "";
                            ConsoleKey key;
                            do
                            {
                                var keyInfo = Console.ReadKey(intercept: true);
                                key = keyInfo.Key;

                                if (key == ConsoleKey.Backspace && password.Length > 0)
                                {
                                    Console.Write("\b \b");
                                    password = password.Substring(0, password.Length - 1);
                                }
                                else if (!char.IsControl(keyInfo.KeyChar))
                                {
                                    Console.Write("*");
                                    password += keyInfo.KeyChar;
                                }
                            } while (key != ConsoleKey.Enter);
                        }
                        creds = new NetworkCredential(username, password, domain);
                    }
                    try
                    {
                        dataSources.Add(new LdapLiveConnector(server, port, creds));
                    }
                    catch (LdapException e)
                    {
                        if (e.ErrorCode == 49)
                            return FailWithError($"unable to authenticate to {server} : invalid username or password");
                        else
                            return FailWithError($"unable to connect to {server} : {e.Message} (code {e.ErrorCode})");
                    }
                }
                else if (args[i] == "oradad")
                {
                    if (i + 1 >= args.Length)
                        return FailWithError("input source 'oradad' requires a path to a directory containing an ORADAD dump");

                    dataSources.Add(new OradadConnector(args[++i]));
                }
                else
                {
                    return FailWithError($"unknown argument '{args[i]}', see --help for usage");
                }
            }

            Engine engine = new Engine(dataSources, templates);

            var partitionDNs = engine.ListPartitionDNs();
            foreach (string partitionDN in partitionDNs)
            {
                results.AddRange(engine.Scan(partitionDN, true));
            }

            if (generalize)
            {
                results = engine.Generalize(results);
            }

            Console.WriteLine($"{results.Count} results:");
            foreach (Result res in results)
            {
                Console.WriteLine(res.ToJson());
            }

            return 0;
        }

        static int FailWithError(string err)
        {
            Console.Error.WriteLine("");
            Console.Error.WriteLine("===============");
            Console.Error.WriteLine("Error, cannot continue: {0}", err);
            Console.Error.WriteLine("===============");
            Console.Error.WriteLine("");
            return 1;
        }

        static int RunGUI(List<Result> templates)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var connectform = new DataSourceDialog();
            var res = connectform.ShowDialog();
            if (res != DialogResult.OK)
            {
                Environment.Exit(1);
            }

            List<Result> results = new List<Result>();
            Engine engine = new Engine(connectform.dataSources.ToArray(), templates);

            if (connectform.dataSources.Count > 0)
            {
                // TODO: multithreading here, with reporting in a GUI status bar
                Console.WriteLine($" [.] Computing from {connectform.dataSources.Count} data sources...");
                foreach (string partitionDN in engine.ListPartitionDNs())
                {
                    results.AddRange(engine.Scan(partitionDN, true));
                }
            }
            else
            {
                Console.WriteLine(" [.] Showing cached results only");
            }

            Application.Run(new TreeWindow(results, new HashSet<string>(engine.ListPartitionDNs())));
            return 0;
        }
    }
}
