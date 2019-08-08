using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Cache;
using System.Text;

namespace Penguin.Authentication.OWA
{
    /// <summary>
    /// Validates an Email/Password combination against Outlook Web Access with the intent of validating organizational domain 
    /// credentials without access to the internal domain server
    /// </summary>
    public class OWAValidator
    {
        #region Constructors

        /// <summary>
        /// Constructs a new instance of the OWA Validator
        /// </summary>
        public OWAValidator()
        {
            this.GetClientId();
            this.Cookies.Add(new Cookie("PrivateComputer", "true", "/", "exchange.postoffice.net"));
            this.Cookies.Add(new Cookie("PBack", "0", "/", "exchange.postoffice.net"));
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Returns true if the given Email/Password combination allows for login on the OWA server
        /// </summary>
        /// <param name="Username"></param>
        /// <param name="Password"></param>
        /// <returns></returns>
        public bool Validate(string Username, string Password)
        {
            string data = string.Format(VALIDATE_FORMAT, Username.Replace("@", "%40"), System.Uri.EscapeUriString(Password));
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(LOGIN_URL);

            request.Timeout = 5000;
            request.Method = "POST";
            request.KeepAlive = true;
            request.ContentLength = data.Length;
            HttpRequestCachePolicy requestPolicy = new HttpRequestCachePolicy(HttpCacheAgeControl.MaxAge, TimeSpan.FromDays(0));
            request.CachePolicy = requestPolicy;
            request.Headers.Add("origin", "https://exchange.postoffice.net");
            request.Headers.Add("Upgrade-Insecure-Requests", "1");
            request.ContentType = "application/x-www-form-urlencoded";
            request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36";
            request.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
            request.Referer = CLIENT_ID_URL;
            request.Headers.Add("Accept-Encoding", "gzip, deflate, br");
            request.Headers.Add("Accept-Language", "en-US,en;q=0.9");
            request.CookieContainer = this.Cookies;

            Stream dataStream = request.GetRequestStream();

            byte[] byteArray = Encoding.UTF8.GetBytes(data);
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();

            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse(); // send request,get response

                dataStream = response.GetResponseStream();
                StreamReader reader = new StreamReader(dataStream);
                string responseFromServer = reader.ReadToEnd();

                return response.ResponseUri.AbsoluteUri.Equals(SUCCESS_URI, StringComparison.CurrentCultureIgnoreCase);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
                return false;
            }
        }

        #endregion Methods

        #region Fields

        private const string CLIENT_ID_URL = "https://exchange.postoffice.net/owa/auth/logon.aspx?replaceCurrent=1&url=https%3a%2f%2fexchange.postoffice.net%2fowa";
        private const string LOGIN_URL = "https://exchange.postoffice.net/owa/auth.owa";
        private const string SUCCESS_URI = "https://exchange.postoffice.net/owa/";
        private const string VALIDATE_FORMAT = "destination=https%3A%2F%2Fexchange.postoffice.net%2Fowa&flags=4&forcedownlevel=0&username={0}&password={1}&passwordText=&trusted=4&isUtf8=1";
        private CookieContainer Cookies = new CookieContainer();

        #endregion Fields

        private static CookieCollection ParseCookieString(string cookieString, Func<string> getCookieDomainIfItIsMissingInCookie)
        {
            bool secure = false;
            bool httpOnly = false;

            string domainFromCookie = null;
            string path = null;
            string expiresString = null;

            Dictionary<string, string> cookiesValues = new Dictionary<string, string>();

            string[] cookieValuePairsStrings = cookieString.Split(';');
            foreach (string cookieValuePairString in cookieValuePairsStrings)
            {
                string[] pairArr = cookieValuePairString.Split('=');
                int pairArrLength = pairArr.Length;
                for (int i = 0; i < pairArrLength; i++)
                {
                    pairArr[i] = pairArr[i].Trim();
                }
                string propertyName = pairArr[0];
                if (pairArrLength == 1)
                {
                    if (propertyName.Equals("httponly", StringComparison.OrdinalIgnoreCase))
                    {
                        httpOnly = true;
                    }
                    else if (propertyName.Equals("secure", StringComparison.OrdinalIgnoreCase))
                    {
                        secure = true;
                    }
                    else
                    {
                        throw new InvalidOperationException(string.Format("Unknown cookie property \"{0}\". All cookie is \"{1}\"", propertyName, cookieString));
                    }

                    continue;
                }

                string propertyValue = pairArr[1];
                if (propertyName.Equals("expires", StringComparison.OrdinalIgnoreCase))
                {
                    expiresString = propertyValue;
                }
                else if (propertyName.Equals("domain", StringComparison.OrdinalIgnoreCase))
                {
                    domainFromCookie = propertyValue;
                }
                else if (propertyName.Equals("path", StringComparison.OrdinalIgnoreCase))
                {
                    path = propertyValue;
                }
                else
                {
                    cookiesValues.Add(propertyName, propertyValue);
                }
            }

            DateTime expiresDateTime;
            if (expiresString != null)
            {
                expiresDateTime = DateTime.Parse(expiresString);
            }
            else
            {
                expiresDateTime = DateTime.MinValue;
            }
            if (string.IsNullOrEmpty(domainFromCookie))
            {
                domainFromCookie = getCookieDomainIfItIsMissingInCookie();
            }

            CookieCollection cookieCollection = new CookieCollection();
            foreach (KeyValuePair<string, string> pair in cookiesValues)
            {
                Cookie cookie = new Cookie(pair.Key, pair.Value, path, domainFromCookie)
                {
                    Secure = secure,
                    HttpOnly = httpOnly,
                    Expires = expiresDateTime
                };

                cookieCollection.Add(cookie);
            }
            return cookieCollection;
        }

        private void GetClientId()
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(CLIENT_ID_URL);

            request.Method = "GET";
            request.KeepAlive = true;
            request.Headers.Add("Upgrade-Insecure-Requests", "1");
            request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36";
            request.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
            request.Headers.Add("Accept-Encoding", "gzip, deflate, br");
            request.Headers.Add("Accept-Language", "en-US,en;q=0.9");

            HttpWebResponse response = (HttpWebResponse)request.GetResponse(); // send request,get response

            for (int i = 0; i < response.Headers.Count; i++)
            {
                string name = response.Headers.GetKey(i);
                if (name != "Set-Cookie")
                {
                    continue;
                }

                string value = response.Headers.Get(i);
                CookieCollection cookieCollection = ParseCookieString(value, () => request.Host.Split(':')[0]);
                response.Cookies.Add(cookieCollection);
            }

            foreach (Cookie c in response.Cookies)
            {
                this.Cookies.Add(c);
            }
        }
    }
}