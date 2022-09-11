using System.Collections.Generic;

namespace DInjector
{
    class ArgumentParser
    {
        public static Dictionary<string, string> Parse(IEnumerable<string> argv)
        {
            var args = new Dictionary<string, string>();

            foreach (var arg in argv)
            {
                var idx = arg.IndexOf(':');

                if (idx > 0)
                    args[arg.Substring(0, idx)] = arg.Substring(idx + 1);
                else
                {
                    idx = arg.IndexOf('=');

                    if (idx > 0)
                        args[arg.Substring(0, idx)] = arg.Substring(idx + 1);
                    else
                        args[arg] = string.Empty;
                }
            }

            return args;
        }
    }
}
