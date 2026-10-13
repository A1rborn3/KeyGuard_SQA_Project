namespace KeyGuard_SQAProject
{
    internal static class Masking
    {
        public static string Mask(string s) //input string s is the raw string to be masked
        {
            if (string.IsNullOrEmpty(s)) return s; //if empty or null, nothing to mask so return
            if (s.Length <= 11) return new string('*', s.Length); // if its length is less than or equal 12, the full thing should be masked to prevent exposing information. this means that at least 4 characters will be masked
            int middleStars = s.Length - 8; // this return the number of middle charactors to be masked as total length minus the first 4 and last 4 charactors
            return s.Substring(0, 4) + new string('*', middleStars) + s.Substring(s.Length - 4); // returns the final masked string with the first 4 characters and last 4 shown
        }
    }
}