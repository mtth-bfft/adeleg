using System;
using System.Collections.Generic;
using System.IO;
using System.Xml.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace adeleg.engine
{
    [XmlType(TypeName = "domain")]
    public struct DomainConfig
    {
        public string server;
        public string domainName;
        public UInt16 port;
        public string userDomain;
        public string userName;
        public string userPassword;
    }

    [XmlRootAttribute("config")]
    public class Config
    {
        private readonly static string APP_DIR = Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA"), "adeleg");
        private readonly static string CONFIG_FILENAME = "config.bin";

        public bool rememberCredentials;

        public string dataSourceTab;

        // LDAP live tab
        public string globalUserDomain;
        public string globalUserName;
        public string globalUserPassword;
        public List<DomainConfig> domains;
        public bool crawlWithinForest;
        public bool crawlAllDomains;

        // ORADAD tab
        public string oradadPath;

        public void Save()
        {
            MemoryStream xmlTextStream = new MemoryStream();
            XmlSerializer serializer = new XmlSerializer(typeof(Config));
            serializer.Serialize(xmlTextStream, this);
            byte[] xmlBytes = xmlTextStream.ToArray();
            byte[] protectedBytes = ProtectedData.Protect(xmlBytes, Encoding.ASCII.GetBytes("adelegconfig"), DataProtectionScope.CurrentUser);
            string configPath = GetDataPath(CONFIG_FILENAME);
            File.WriteAllBytes(configPath, protectedBytes);
            Console.WriteLine($" [.] Config saved to {configPath}");
        }

        public static Config Load()
        {
            string configPath = GetDataPath(CONFIG_FILENAME);
            if (File.Exists(configPath))
            {
                try
                {
                    byte[] protectedBytes = File.ReadAllBytes(configPath);
                    byte[] xmlBytes = ProtectedData.Unprotect(protectedBytes, Encoding.ASCII.GetBytes("adelegconfig"), DataProtectionScope.CurrentUser);
                    MemoryStream xmlTextStream = new MemoryStream(xmlBytes);
                    XmlSerializer deserializer = new XmlSerializer(typeof(Config));
                    Config conf = (Config)deserializer.Deserialize(xmlTextStream);
                    return conf;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(" [!] Unable to load previous configuration from disk: " + ex);
                }
            }
            return new Config();
        }

        public static string GetDataPath(string fileName = null)
        {
            Directory.CreateDirectory(APP_DIR);
            if (fileName == null)
            {
                return APP_DIR;
            }
            else
            {
                return Path.Combine(APP_DIR, fileName);
            }
        }
    }
}
