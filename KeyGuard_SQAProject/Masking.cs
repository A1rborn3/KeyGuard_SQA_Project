namespace KeyGuard_SQAProject
{
    internal static class Masking
    {
        public static string Mask(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            if (s.Length <= 8) return new string('*', s.Length);
            int middleStars = Math.Max(4, s.Length - 8);
            return s.Substring(0, 4) + new string('*', middleStars) + s.Substring(s.Length - 4);
        }
    }
}