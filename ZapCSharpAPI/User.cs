using Newtonsoft.Json;
using OWASPZAPDotNetAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZapCSharpAPI
{
    public class User
    {
        public String Id { get; set; }
        bool Enabled { get; set; }
        String ContextId { get; set; }
        String Name { get; set; }
        Dictionary<String, String> Credentials { get; set; }
        
        public User(ApiResponseSet apiResponseSet)  {
            Id = apiResponseSet.Dictionary["id"];
            Enabled = Boolean.Parse(apiResponseSet.Dictionary["enabled"]);
            ContextId = apiResponseSet.Dictionary["contextId"];
            Name = apiResponseSet.Dictionary["name"];
            Credentials = JsonConvert.DeserializeObject<Dictionary<string, string>>(apiResponseSet.Dictionary["credentials"]);
        }
    }
}
