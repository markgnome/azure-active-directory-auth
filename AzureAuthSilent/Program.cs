using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AzureAuthSilent
{
    class Program
    {
        static void Main(string[] args)
        {
            
            // Wait for it to finish

            // Get the result
            var token = AdalAuthentication();
            // Write it our
        }

        private static string AdalAuthentication()
        {
            try
            {
                var tenant = "markgnomegmail.onmicrosoft.com";
                var serviceUri = "https://markgnomegmail.onmicrosoft.com/SinglePageApp-DotNet";
                var clientID = "98b83286-6d5c-4297-a485-2d2dc153349d";
                var userName = $"RedMap@{tenant}";
                var password = "a9VKChrXLJvvGKpp1";
                string responsebody;
                //  Ceremony
                //var authority = "https://login.microsoftonline.com/" + tenant;
                //var authContext = new AuthenticationContext(authority);
                //var credentials = new UserPasswordCredential(userName, password);
                //var authResult = authContext.AcquireTokenAsync(serviceUri, clientID, credentials).Result;
                //return authResult.AccessToken;
                using (var webClient = new WebClient())
                {
                    var requestParameters = new NameValueCollection();

                    requestParameters.Add("resource", serviceUri);
                    requestParameters.Add("client_id", clientID);
                    requestParameters.Add("grant_type", "password");
                    requestParameters.Add("username", userName);
                    requestParameters.Add("password", password);
                    requestParameters.Add("scope", "openid");

                    var url = $"https://login.microsoftonline.com/{tenant}/oauth2/token";
                    var responsebytes = webClient.UploadValuesTaskAsync(url, "POST", requestParameters).Result;
                    responsebody = Encoding.UTF8.GetString(responsebytes);
                }

                return responsebody;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            //  Constants
         
        }
    }

    class NaiveSessionCache : TokenCache
    {
        private static readonly object FileLock = new object();
        private readonly string CacheId = string.Empty;
        private string UserObjectId = string.Empty;
        private readonly HttpContext _httpContext;

        public NaiveSessionCache(string userId)
        {
            _httpContext = HttpContext.Current;
            UserObjectId = userId;
            CacheId = UserObjectId + "_TokenCache";

            AfterAccess = AfterAccessNotification;
            BeforeAccess = BeforeAccessNotification;
            Load();
        }

        public void Load()
        {
            lock (FileLock)
            {
                if (_httpContext != null)
                {
                    Deserialize((byte[]) _httpContext.Session[CacheId]);
                }
            }
        }

        public void Persist()
        {
            lock (FileLock)
            {
                if (_httpContext != null)
                {
                    // reflect changes in the persistent store
                    _httpContext.Session[CacheId] = Serialize();
                    // once the write operation took place, restore the HasStateChanged bit to false
                    HasStateChanged = false;
                }
            }
        }

        // Empties the persistent store.
        public override void Clear()
        {
            base.Clear();
            if (_httpContext != null)
            {
                _httpContext.Session.Remove(CacheId);
            }
        }

        public override void DeleteItem(TokenCacheItem item)
        {
            base.DeleteItem(item);
            Persist();
        }

        // Triggered right before ADAL needs to access the cache.
        // Reload the cache from the persistent store in case it changed since the last access.
        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            Load();
        }

        // Triggered right after ADAL accessed the cache.
        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (HasStateChanged)
            {
                Persist();
            }
        }
    }
}
