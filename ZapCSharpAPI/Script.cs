using OWASPZAPDotNetAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZapCSharpAPI
{
    public class Script
    {
        public Script(ApiResponseSet apiResponseSet)
        {
            Name = apiResponseSet.Dictionary["name"];
            Type = apiResponseSet.Dictionary["type"];
            Engine = apiResponseSet.Dictionary["engine"];
            Error = Boolean.Parse(apiResponseSet.Dictionary["error"]);
            Description = apiResponseSet.Dictionary["description"];
        }

        public String Name {get; set;}
        public String Type {get; set;}
        public String Engine {get; set;}
        public bool Error {get; set;}
        public String Description {get; set;}
    }
}
