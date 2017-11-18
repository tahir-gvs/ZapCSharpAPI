using OWASPZAPDotNetAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ZapCSharpAPI
{
    public class Context
    {
            public Context(ApiResponseSet response)
            {
                Id = response.Dictionary["id"];
                Name = response.Dictionary["name"];
                Description = response.Dictionary["description"];
                LoggedInPattern = response.Dictionary["loggedInPattern"];
                LoggedOutPattern = response.Dictionary["loggedOutPattern"];
                string includedRegexsNode = response.Dictionary["includeRegexs"];
                if (includedRegexsNode.Length > 2)
                {
                    IncludedRegexs = (includedRegexsNode.Substring(1, includedRegexsNode.Length - 1).Split(", ".ToCharArray())).ToList();
                }
                string excludedRegexsNode = response.Dictionary["excludeRegexs"];
                if (excludedRegexsNode.Length > 2)
                {
                    ExcludedRegexs = (excludedRegexsNode.Substring(1, excludedRegexsNode.Length - 1).Split(", ".ToCharArray())).ToList();
                }
                AuthType = response.Dictionary["authType"];
                AuthenticationDetectionMethodId = Int32.Parse(response.Dictionary["authenticationDetectionMethodId"]);
            }

            public string Id {get; set;}
        
            public string Name{get; set;}

            public string Description{get; set;}

            public string LoggedInPattern{get; set;}

            public string LoggedOutPattern{get; set;}

            public List<string> IncludedRegexs {get; set;}

            public List<string> ExcludedRegexs{get; set;}

            public string AuthType {get; set;}

            public int AuthenticationDetectionMethodId{get; set;}
     }
    
}
