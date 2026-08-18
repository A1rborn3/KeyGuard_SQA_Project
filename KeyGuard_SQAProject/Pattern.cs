using System.Text.RegularExpressions;

namespace KeyGuard_SQAProject
{
    internal sealed class Pattern
    {
        public string Name { get; }
        public Regex Regex { get; }
        public bool UseLuhnForDigits { get; }

        public Pattern(string name, string pattern, RegexOptions options = RegexOptions.Compiled | RegexOptions.IgnoreCase, bool useLuhn = false)
        {
            Name = name;
            Regex = new Regex(pattern, options);
            UseLuhnForDigits = useLuhn;
        }
    }
}