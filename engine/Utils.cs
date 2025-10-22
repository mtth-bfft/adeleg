using System;
using System.Collections.Generic;

namespace adeleg.engine
{
    internal class Utils
    {
        public static Tuple<string, string> SplitDn(string dn, HashSet<string> partitionDNs)
        {
            int splitPos = -1;

            // Don't try to split above domain components
            if (!partitionDNs.Contains(dn.ToLower()))
            {
                bool escaped = false;
                for (int i = 0; i < dn.Length; i++)
                {
                    if (dn[i] == '\\')
                        escaped = !escaped;

                    if (dn[i] == ',' && !escaped)
                    {
                        splitPos = i;
                        break;
                    }
                }
            }
            if (splitPos < 0)
            {
                return Tuple.Create<string, string>(dn, null);
            }
            else
            {
                return Tuple.Create(dn.Substring(0, splitPos), dn.Substring(splitPos + 1));
            }
        }
    }
}
