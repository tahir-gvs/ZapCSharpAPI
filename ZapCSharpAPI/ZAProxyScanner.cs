using OpenQA.Selenium;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OWASPZAPDotNetAPI;
using System.Text.RegularExpressions;
using System.Net;
using Newtonsoft.Json;

namespace ZapCSharpAPI
{
    public class ZAProxyScanner
    {
    private static string MINIMUM_ZAP_VERSION = "2.6"; 
    private ClientApi clientApi;
    private Proxy seleniumProxy;
    private string apiKey;
    //Logger log = Logger.getLogger(ZAProxyScanner.class.getName());

    //throws IllegalArgumentException, ProxyException
    public ZAProxyScanner(string host, int port, string apiKey)
             {
        validateHost(host);
        validatePort(port);
        this.apiKey = apiKey;

        clientApi = new ClientApi(host, port, this.apiKey);
        validateMinimumRequiredZapVersion();

        seleniumProxy = new Proxy();
        seleniumProxy.Kind = ProxyKind.ProxyAutoConfigure;
        StringBuilder strBuilder = new StringBuilder();
        strBuilder.Append("http://").Append(host).Append(":").Append(port).Append("/proxy.pac?apikey=").Append(this.apiKey);
        seleniumProxy.ProxyAutoConfigUrl=strBuilder.ToString();
    }

    private static void validateHost(String host) {
        if (host == null) {
            throw new SystemException("Parameter host must not be null.");
        }
        if (host.Length == 0) {
            throw new SystemException("Parameter host must not be empty.");
        }
    }

    private static void validatePort(int port) {
        if (port <= 0 || port > 65535) {
            throw new SystemException("Parameter port must be between 1 and 65535.");
        }
    }

    private static bool validZAPVersion(String expected, String given) {

        string[] expectedVersion = expected.Split("\\.".ToCharArray());
        string[] givenVersion = given.Split("\\.".ToCharArray());

        // Assumption: If the version # doesn't have ".", it is weekly build.
        if (givenVersion.Length == 1) {
            return true;
        }

        for (int i = 0; i < expectedVersion.Length; i++) {
            if (i < expectedVersion.Length) {
                if (Int32.Parse(givenVersion[i]) < Int32.Parse(expectedVersion[i])) {
                    return false;
                }
                if (Int32.Parse(givenVersion[i]) > Int32.Parse(expectedVersion[i])) {
                    return true;
                }
            }
        }

        return true;
    }

    private void validateMinimumRequiredZapVersion()  {
            String zapVersion = ((ApiResponseElement) clientApi.core.version()).Value;

            bool minimumRequiredZapVersion;
            minimumRequiredZapVersion = validZAPVersion(MINIMUM_ZAP_VERSION, zapVersion);

            if (!minimumRequiredZapVersion) {
                throw new SystemException("Minimum required ZAP version not met, expected >= \""
                        + MINIMUM_ZAP_VERSION + "\" but got: " + zapVersion);
            }
    }

    public void setScannerAttackStrength(string scannerId, string strength) {
            clientApi.ascan.setScannerAttackStrength(this.apiKey, scannerId, strength, null);
    }

    
    public void setScannerAlertThreshold(String scannerId, String threshold) {
            clientApi.ascan.setScannerAlertThreshold(this.apiKey, scannerId, threshold, null);
    }

    public void setEnableScanners(string ids, bool enabled) {

            if(enabled) {
                clientApi.ascan.enableScanners(this.apiKey, ids, null);
            } else {
                clientApi.ascan.disableScanners(this.apiKey, ids, null);
            }
    }

    public void disableAllScanners() {
            IApiResponse response = clientApi.pscan.setEnabled(this.apiKey, "false");
            response = clientApi.ascan.disableAllScanners(this.apiKey, null);
    }

    public void enableAllScanners() {
            clientApi.pscan.setEnabled(this.apiKey, "true");
            clientApi.ascan.enableAllScanners(this.apiKey, null);
    }

    public void setEnablePassiveScan(bool enabled) {
            clientApi.pscan.setEnabled(this.apiKey, enabled.ToString());
    }

    public List<Alert> getAlerts() {
        return getAlerts(-1, -1);
    }

    public void deleteAlerts() {
        clientApi.core.deleteAllAlerts(this.apiKey);
    }

    public byte[] getXmlReport() {
        return clientApi.core.xmlreport(this.apiKey);
    }

    public byte[] getHtmlReport() {
            return clientApi.core.htmlreport(this.apiKey);
    }

    public List<Alert> getAlerts(int start, int count) {
            return clientApi.GetAlerts("", start, count);
    }

    public int getAlertsCount() {
            return ClientApiUtils.getInteger(clientApi.core.numberOfAlerts(""));
    }

    public void scan(String url) {
            clientApi.ascan.scan(this.apiKey, url, "true", "false", null, null, null, null);
    }

    /**
     * Performs the Active Scan with the given parameters and configuration.
     *
     * @param url       Url to active scan.
     * @param contextId Id of the context.
     * @param userId    Id of the user.
     * @param recurse   Flag to perform the active scan recursively.
     * @throws ProxyException
     */
    public void scanAsUser(String url, String contextId, String userId, bool recurse)
    {
            this.clientApi.ascan
                    .scanAsUser(this.apiKey,url, contextId, userId, recurse.ToString(),
                            null, null, null);
    }

    public int getScanProgress(int id) {
            ApiResponseList response = (ApiResponseList) clientApi.ascan.scans();
            ApiResponseSet scanResponse = (ApiResponseSet)response.List.First(s => ((ApiResponseSet)s).Dictionary["id"].Equals(id.ToString()));
            return Int32.Parse(scanResponse.Dictionary["progress"]);
    }

    public void clear() {
            clientApi.ascan.removeAllScans(this.apiKey);
            clientApi.core.newSession(this.apiKey, "", "");
    }

    public IList<HarSharp.Entry> getHistory() {
        return getHistory(-1, -1);
    }

    public IList<HarSharp.Entry> getHistory(int start, int count)  {
            return ClientApiUtils.getHarEntries(clientApi.core
                    .messagesHar(this.apiKey,"", start.ToString(), count.ToString()));
    }

    public int getHistoryCount() {
       return ClientApiUtils.getInteger(clientApi.core.numberOfMessages(""));
    }

    public List<HarSharp.Entry> findInResponseHistory(String regex, List<HarSharp.Entry> entries) {
        List<HarSharp.Entry> found = new List<HarSharp.Entry>();
        foreach (HarSharp.Entry entry in entries) {
            if (entry.Response.Content != null) {
                String content = entry.Response.Content.Text;
                if ("base64".Equals(entry.Response.Content.Encoding, StringComparison.InvariantCultureIgnoreCase)) {
                    content = Encoding.UTF8.GetString(Convert.FromBase64String(content));
                }
                if (content.Contains(regex)) {
                    found.Add(entry);
                }
            }
        }
        return found;
    }

    public IList<HarSharp.Entry> findInRequestHistory(String regex)  {
            return ClientApiUtils
                    .getHarEntries(clientApi.search.harByRequestRegex(this.apiKey, regex, "", "-1", "-1"));
    }

    public IList<HarSharp.Entry> findInResponseHistory(String regex) {
            return ClientApiUtils
                    .getHarEntries(clientApi.search.harByResponseRegex(this.apiKey, regex, "", "-1", "-1"));
    }

    public IList<HarSharp.Entry> makeRequest(HarSharp.Request request, bool followRedirect) {
            String harRequestStr = ClientApiUtils.convertHarRequestToString(request);
            byte[] response = clientApi.core.sendHarRequest(this.apiKey, harRequestStr, followRedirect.ToString());
            String responseAsString = Encoding.UTF8.GetString(response);
            return ClientApiUtils.getHarEntries(response);
    }

    public Proxy getSeleniumProxy() {
        return seleniumProxy;
    }

    public void spider(string url, Int32 maxChildren, bool recurse, string contextName) {
        // Defaulting the context to "Default Context" in ZAP
        String contextNameString = contextName == null ? "Default Context" : contextName;
        String maxChildrenString = maxChildren.ToString();
        clientApi.spider
                .scan(this.apiKey, url, maxChildrenString, recurse.ToString(), contextNameString, null);
    }

    public void spider(string url) {

            clientApi.spider
                    .scan(this.apiKey, url, null, null, null, null);
    }

    public void spider(string url, bool recurse, string contextName) {
        //Something must be specified else zap throws an exception
        String contextNameString = contextName == null ? "Default Context" : contextName;
            clientApi.spider
                    .scan(this.apiKey, url, null, recurse.ToString(), contextNameString, null);
    }

    public void spiderAsUser(string url, string contextId, string userId) {
        clientApi.spider
                    .scanAsUser(this.apiKey, url, contextId, userId, null, null, null);
    }

    public void spiderAsUser(string url, string contextId, string userId, bool recurse) {
            clientApi.spider
                    .scanAsUser(this.apiKey, url, contextId, userId, null, recurse.ToString(), null);
    }

    public void spiderAsUser(String url, String contextId, String userId,
                             Int32 maxChildren, bool recurse) {
            clientApi.spider
                    .scanAsUser(this.apiKey, url, contextId, userId, maxChildren.ToString(), recurse.ToString(), null);
    }

    public void excludeFromSpider(string regex) {
            clientApi.spider.excludeFromScan(this.apiKey, regex);
    }

    public void excludeFromScanner(String regex) {
            clientApi.ascan.excludeFromScan(this.apiKey, regex);
    }

    public void setAttackMode() {
            clientApi.core.setMode(this.apiKey, "attack");
    }

    public void setMaxDepth(int depth) {
            clientApi.spider.setOptionMaxDepth(this.apiKey, depth);
    }

    public void setPostForms(bool post) {
            clientApi.spider.setOptionPostForm(this.apiKey, post);
    }

    public void setThreadCount(int threads) {
            clientApi.spider.setOptionThreadCount(this.apiKey, threads);
    }

    public int getLastSpiderScanId() {
            ApiResponseList response = (ApiResponseList) clientApi.spider.scans();
            return (new ScanResponse(response)).getLastScan().Id;
    }

    public int getLastScannerScanId() {
            ApiResponseList response = (ApiResponseList) clientApi.ascan.scans();
            return (new ScanResponse(response)).getLastScan().Id;
    }

    public int getSpiderProgress(int id) {
            ApiResponseList response = (ApiResponseList) clientApi.spider.scans();
            return new ScanResponse(response).getScanById(id).Progress;
    }

    public List<String> getSpiderResults(int id) {
        List<String> results = new List<string>();
            ApiResponseList responseList = (ApiResponseList) clientApi.spider
                    .results(id.ToString());
            foreach (IApiResponse response in responseList.List) {
                results.Add(((ApiResponseElement) response).Value);
            }
        return results;
    }

    /**
     * Shuts down ZAP.
     *
     * @throws ProxyException
     */
    public void shutdown() {
            clientApi.core.shutdown(this.apiKey);
    }

    /**
     * Enables handling of anti CSRF tokens during active scanning.
     *
     * @param enabled Boolean flag to enable / disable handling of anti CSRF tokens during active scan.
     * @throws ProxyException
     */
    public void setOptionHandleAntiCSRFTokens(bool enabled) {
            clientApi.ascan.setOptionHandleAntiCSRFTokens(this.apiKey, enabled);
    }

    /**
     * Creates a new context with given context name and sets it in scope if @param inScope is true.
     *
     * @param contextName Name of the context.
     * @param inScope     true to set context in scope.
     * @throws ProxyException
     */
    public void createContext(string contextName, bool inScope) {
            clientApi.context.newContext(this.apiKey, contextName);
            clientApi.context.setContextInScope(this.apiKey, contextName, inScope.ToString());
    }

    /**
     * Adds include regex to the given context.
     *
     * @param contextName Name of the context.
     * @param regex       URL to include in context.
     * @throws ProxyException
     */
    public void includeRegexInContext(string contextName, Regex regex) {
            clientApi.context.includeInContext(this.apiKey, contextName, Regex.Escape(regex.ToString()));
    }

    /**
     * Adds include parent url to the given content.
     *
     * @param contextName Name of the context.
     * @param parentUrl   Parent URL to include in context.
     * @throws ProxyException
     */
    public void includeUrlTreeInContext(string contextName, string parentUrl)
    {
        Regex pattern = new Regex(parentUrl);
            clientApi.context
                    .includeInContext(this.apiKey, contextName, Regex.Escape(pattern.ToString()) + ".*");
    }

    /**
     * Add exclude regex to the given context.
     *
     * @param contextName Name of the context.
     * @param regex       Regex to exclude from context.
     * @throws ProxyException
     */
    public void excludeRegexFromContext(string contextName, Regex regex) {
            clientApi.context.excludeFromContext(this.apiKey, contextName, Regex.Escape(regex.ToString()));
    }

    /**
     * Add exclude regex to the given context.
     *
     * @param contextName Name of the context.
     * @param parentUrl   Parent URL to exclude from context.
     * @throws ProxyException
     */
    public void excludeParentUrlFromContext(string contextName, string parentUrl)
    {
        Regex pattern = new Regex(parentUrl);
            clientApi.context
                    .excludeFromContext(this.apiKey, contextName, Regex.Escape(pattern.ToString()) + ".*");
    }

    /**
     * Returns Context details for a given context name.
     *
     * @param contextName Name of context.
     * @return Context details for the given context
     * @throws ProxyException
     */
    public Context getContextInfo(string contextName) {
        clientApi.context.context(contextName);
        Context context = new Context((ApiResponseSet) clientApi.context.context(contextName));
        return context;
    }

    /**
     * Returns list of context names.
     *
     * @return List of context names.
     * @throws ProxyException
     */
    public List<String> getContexts() {
        string contexts = ((ApiResponseElement) clientApi.context.contextList()).Value;
        return (contexts.Substring(1, contexts.Length - 1).Split(", ".ToCharArray())).ToList();
    }

    /**
     * Sets the given context in or out of scope.
     *
     * @param contextName Name of the context.
     * @param inScope     true - Sets the context in scope. false - Sets the context out of scope.
     * @throws ProxyException
     */
    public void setContextInScope(String contextName, bool inScope) {
        clientApi.context.setContextInScope(this.apiKey, contextName, inScope.ToString());
    }

    /**
     * Returns the list of included regexs for the given context.
     *
     * @param contextName Name of the context.
     * @return List of include regexs.
     * @throws ProxyException
     */
    public List<String> getIncludedRegexs(String contextName) {
        String includedRegexs;
            includedRegexs = ((ApiResponseElement) clientApi.context.includeRegexs(contextName))
                    .Value;
            if (includedRegexs.Length > 2) {
                return (includedRegexs.Substring(1, includedRegexs.Length - 1).Split(", ".ToCharArray())).ToList();
            }
        return null;
    }

    /**
     * Returns the list of excluded regexs for the given context.
     *
     * @param contextName Name of the context.
     * @return List of exclude regexs.
     * @throws ProxyException
     */
    public List<String> getExcludedRegexs(String contextName) {
        String excludedRegexs = null;
            excludedRegexs = ((ApiResponseElement) clientApi.context.excludeRegexs(contextName))
                    .Value;
        if (excludedRegexs.Length > 2) {
            return (excludedRegexs.Substring(1, excludedRegexs.Length - 1).Split(", ".ToCharArray())).ToList();
        }
        return null;
    }

    /**
     * Returns the supported authentication methods by ZAP.
     *
     * @return list of supported authentication methods.
     * @throws ProxyException
     */
    public List<String> getSupportedAuthenticationMethods() {
        ApiResponseList apiResponseList = null;
            apiResponseList = (ApiResponseList) clientApi.authentication
                    .getSupportedAuthenticationMethods();
        List<String> supportedAuthenticationMethods = new List<String>();
        foreach (IApiResponse apiResponse in apiResponseList.List) {
            supportedAuthenticationMethods.Add(((ApiResponseElement) apiResponse).Value);
        }
        return supportedAuthenticationMethods;
    }

    /**
     * Returns logged in indicator pattern for the given context.
     *
     * @param contextId Id of the context.
     * @return Logged in indicator for the given context.
     * @throws ProxyException
     */
    public String getLoggedInIndicator(String contextId) {
            return ((ApiResponseElement) clientApi.authentication.getLoggedInIndicator(contextId))
                    .Value;
    }

    /**
     * Returns logged out indicator pattern for the given context.
     *
     * @param contextId Id of the context.
     * @return Logged out indicator for the given context.
     * @throws ProxyException
     */
    public String getLoggedOutIndicator(String contextId) {
            return ((ApiResponseElement) clientApi.authentication.getLoggedOutIndicator(contextId))
                    .Value;
    }

    /**
     * Sets the logged in indicator to a given context.
     *
     * @param contextId              Id of a context.
     * @param loggedInIndicatorRegex Regex pattern for logged in indicator.
     * @throws ProxyException
     */
    public void setLoggedInIndicator(String contextId, String loggedInIndicatorRegex)
            {
            clientApi.authentication
                    .setLoggedInIndicator(this.apiKey, contextId, Regex.Escape(loggedInIndicatorRegex));
    }

    /**
     * Sets the logged out indicator to a given context.
     *
     * @param contextId               Id of a context.
     * @param loggedOutIndicatorRegex Regex pattern for logged out indicator.
     * @throws ProxyException
     */
    public void setLoggedOutIndicator(String contextId, String loggedOutIndicatorRegex)
             {
            clientApi.authentication
                    .setLoggedOutIndicator(this.apiKey, contextId, Regex.Escape(loggedOutIndicatorRegex));
    }

    /**
     * Returns authentication method info for a given context.
     *
     * @param contextId Id of a context.
     * @return Authentication method name for the given context id.
     * @throws ProxyException
     */
    public Dictionary<String, String> getAuthenticationMethodInfo(String contextId) {
        Dictionary<String, String> authenticationMethodDetails = new Dictionary<String, String>();
        IApiResponse apiResponse = apiResponse = clientApi.authentication.getAuthenticationMethod(contextId);
        if (apiResponse is ApiResponseElement) {
            authenticationMethodDetails
                    .Add("methodName", ((ApiResponseElement) apiResponse).Value);
        } else if (apiResponse is ApiResponseSet) {
            ApiResponseSet apiResponseSet = (ApiResponseSet) apiResponse;
            String authenticationMethod = apiResponseSet.Dictionary["methodName"];
            authenticationMethodDetails.Add("methodName", authenticationMethod);

            if (authenticationMethod
                    .Equals(AuthenticationMethod.FORM_BASED_AUTHENTICATION.getValue())) {
                List<Dictionary<string, string>> configParameters = getAuthMethodConfigParameters(
                        AuthenticationMethod.FORM_BASED_AUTHENTICATION.getValue());
                foreach(Dictionary<string, string> configParameter in configParameters) {
                    authenticationMethodDetails.Add(configParameter["name"],
                            apiResponseSet.Dictionary[configParameter["name"]]);
                }
            } else if (authenticationMethod
                    .Equals(AuthenticationMethod.HTTP_AUTHENTICATION.getValue())) {
                // Cannot dynamically populate the values for httpAuthentication, as one of the parameters in getAuthMethodConfigParameters (hostname) is different to what is returned here (host).
                authenticationMethodDetails.Add("host", apiResponseSet.Dictionary["host"]);
                authenticationMethodDetails.Add("realm", apiResponseSet.Dictionary["realm"]);
                authenticationMethodDetails.Add("port", apiResponseSet.Dictionary["port"]);
            } else if (authenticationMethod
                    .Equals(AuthenticationMethod.SCRIPT_BASED_AUTHENTICATION.getValue())) {
                authenticationMethodDetails
                        .Add("scriptName", apiResponseSet.Dictionary["scriptName"]);
                authenticationMethodDetails.Add("LoginURL", apiResponseSet.Dictionary["LoginURL"]);
                authenticationMethodDetails.Add("Method", apiResponseSet.Dictionary["Method"]);
                authenticationMethodDetails.Add("Domain", apiResponseSet.Dictionary["Domain"]);
                authenticationMethodDetails.Add("Path", apiResponseSet.Dictionary["Path"]);
            }
        }
        return authenticationMethodDetails;
    }

    /**
     * Returns the authentication method info as a string.
     *
     * @param contextId Id of a context.
     * @return Authentication method info as a String.
     * @throws ProxyException
     */
    public String getAuthenticationMethod(String contextId) {
            return clientApi.authentication.getAuthenticationMethod(contextId).ToString();
    }

    /**
     * Returns the list of authentication config parameters.
     * Each config parameter is a map with keys "name" and "mandatory", holding the values name of the configuration parameter and whether it is mandatory/optional respectively.
     *
     * @param authMethod Valid authentication method name.
     * @return List of configuration parameters for the given authentication method name.
     * @throws ProxyException
     */
    public List<Dictionary<String, String>> getAuthMethodConfigParameters(String authMethod)
    {
        ApiResponseList apiResponseList = null;
            apiResponseList = (ApiResponseList) clientApi.authentication
                    .getAuthenticationMethodConfigParams(authMethod);
        return getConfigParams(apiResponseList);
    }

    private List<Dictionary<String, String>> getConfigParams(ApiResponseList apiResponseList) {
        List<Dictionary<String, String>> fields = new List<Dictionary<String, String>>(
                apiResponseList.List.Count);
        foreach(ApiResponseSet apiResponseSet in apiResponseList.List) {
            Dictionary<String, String> field = new Dictionary<String, String>();
            //           attributes field in apiResponseSet is not initialized with the keys from the map. So, there is no way to dynamically obtain the keys beside looking for "name" and "mandatory".
            //            List<String> attributes = Arrays.asList(apiResponseSet.getAttributes());
            //            for (String attribute : attributes) {
            //                field.put(attribute, apiResponseSet.getAttribute(attribute));
            //            }
            field.Add("name", apiResponseSet.Dictionary["name"]);
            field.Add("mandatory", apiResponseSet.Dictionary["mandatory"]);
            fields.Add(field);
        }

        return fields;
    }

    /**
     * Sets the authentication method for a given context with given configuration parameters.
     *
     * @param contextId              Id of a context.
     * @param authMethodName         Valid authentication method name.
     * @param authMethodConfigParams Authentication method configuration parameters such as loginUrl, loginRequestData formBasedAuthentication method, and hostName, port, realm for httpBasedAuthentication method.
     * @throws ProxyException
     */
    public void setAuthenticationMethod(String contextId, String authMethodName,
                                        String authMethodConfigParams){
            clientApi.authentication
                    .setAuthenticationMethod(this.apiKey, contextId, authMethodName, authMethodConfigParams);
    }

    /**
     * Sets the formBasedAuthentication to given context id with the loginUrl and loginRequestData.
     * Example loginRequestData: "username={%username%}&password={%password%}"
     *
     * @param contextId        Id of the context.
     * @param loginUrl         Login URL.
     * @param loginRequestData Login request data with form field names for username and password.
     * @throws ProxyException
     * @throws UnsupportedEncodingException
     */
    public void setFormBasedAuthentication(String contextId, String loginUrl,
                                           String loginRequestData) {
        setAuthenticationMethod(contextId, AuthenticationMethod.FORM_BASED_AUTHENTICATION.getValue(),
                "loginUrl=" + WebUtility.UrlEncode(loginUrl) + "&loginRequestData=" + WebUtility.UrlEncode(loginRequestData));
    }

    /**
     * Sets the HTTP/NTLM authentication to given context id with hostname, realm and port.
     *
     * @param contextId  Id of the context.
     * @param hostname   Hostname.
     * @param realm      Realm.
     * @param portNumber Port number.
     * @throws ProxyException
     */
    public void setHttpAuthentication(String contextId, String hostname, String realm,
                                      String portNumber) {
        
        if (portNumber.Trim().Length > 0) {
            setAuthenticationMethod(contextId, AuthenticationMethod.HTTP_AUTHENTICATION.getValue(),
                    "hostname=" + WebUtility.UrlEncode(hostname) + "&realm=" + WebUtility
                            .UrlEncode(realm) + "&port=" + WebUtility.UrlEncode(portNumber));
        } else {
            setHttpAuthentication(contextId, hostname, realm);
        }
    }

    /**
     * Sets the HTTP/NTLM authentication to given context id with hostname, realm.
     *
     * @param contextId Id of the context.
     * @param hostname  Hostname.
     * @param realm     Realm.
     * @throws ProxyException
     */
    public void setHttpAuthentication(String contextId, String hostname, String realm)
    {
        setAuthenticationMethod(contextId, AuthenticationMethod.HTTP_AUTHENTICATION.getValue(),
                "hostname=" + WebUtility.UrlEncode(hostname) + "&realm=" + WebUtility
                        .UrlEncode(realm));
    }

    /**
     * Sets the manual authentication to the given context id.
     *
     * @param contextId Id of the context.
     * @throws ProxyException
     */

    public void setManualAuthentication(String contextId) {
        setAuthenticationMethod(contextId, AuthenticationMethod.MANUAL_AUTHENTICATION.getValue(),
                null);
    }

    /**
     * Sets the script based authentication to the given context id with the script name and config parameters.
     *
     * @param contextId          Id of the context.
     * @param scriptName         Name of the script.
     * @param scriptConfigParams Script config parameters.
     * @throws ProxyException
     */
    public void setScriptBasedAuthentication(String contextId, String scriptName,
                                             String scriptConfigParams){
        setAuthenticationMethod(contextId,
                AuthenticationMethod.SCRIPT_BASED_AUTHENTICATION.getValue(),
                "scriptName=" + scriptName + "&" + scriptConfigParams);
    }

    /**
     * Returns list of {@link User}s for a given context.
     *
     * @param contextId Id of the context.
     * @return List of {@link User}s
     * @throws ProxyException
     * @throws IOException
     */
    public List<User> getUsersList(String contextId) {
        ApiResponseList apiResponseList;

            apiResponseList = (ApiResponseList) clientApi.users.usersList(contextId);
        List<User> users = new List<User>();
        if (apiResponseList != null) {
            foreach (IApiResponse apiResponse in apiResponseList.List) {
                users.Add(new User((ApiResponseSet) apiResponse));
            }
        }
        return users;
    }

    /**
     * Returns the {@link User} info for a given context id and user id.
     *
     * @param contextId Id of a context.
     * @param userId    Id of a user.
     * @return {@link User} info.
     * @throws ProxyException
     * @throws IOException
     */
    public User getUserById(String contextId, String userId) {
            return new User((ApiResponseSet) clientApi.users.getUserById(contextId, userId));
    }

    /**
     * Returns list of config parameters of authentication credentials for a given context id.
     * Each item in the list is a map with keys "name" and "mandatory".
     *
     * @param contextId Id of a context.
     * @return List of authentication credentials configuration parameters.
     * @throws ProxyException
     */
    public List<Dictionary<String, String>> getAuthenticationCredentialsConfigParams(String contextId) {
        ApiResponseList apiResponseList = (ApiResponseList) clientApi.users
                    .getAuthenticationCredentialsConfigParams(contextId);
        return getConfigParams(apiResponseList);
    }

    /**
     * Returns the authentication credentials as a map with key value pairs for a given context id and user id.
     *
     * @param contextId Id of a context.
     * @param userId    Id of a user.
     * @return Authentication credentials.
     * @throws ProxyException
     */
    public Dictionary<String, String> getAuthenticationCredentials(String contextId, String userId)
    {
        Dictionary<String, String> credentials = new Dictionary<String, String>();
        ApiResponseSet apiResponseSet = (ApiResponseSet) clientApi.users
                    .getAuthenticationCredentials(contextId, userId);

        String type = apiResponseSet.Dictionary["type"];
        credentials.Add("type", type);
        if (type.Equals("UsernamePasswordAuthenticationCredentials")) {
            credentials.Add("username", apiResponseSet.Dictionary["username"]);
            credentials.Add("password", apiResponseSet.Dictionary["password"]);
        } else if (type.Equals("ManualAuthenticationCredentials")) {
            credentials.Add("sessionName", apiResponseSet.Dictionary["sessionName"]);
        } else if (type.Equals("GenericAuthenticationCredentials")) {
            if (apiResponseSet.Dictionary.ContainsKey("username") ) {
                credentials.Add("username", apiResponseSet.Dictionary["username"]);
            }
            if (apiResponseSet.Dictionary.ContainsKey("password")) {
                credentials.Add("password", apiResponseSet.Dictionary["password"]);
            }
            if (apiResponseSet.Dictionary.ContainsKey("Username")) {
                credentials.Add("Username", apiResponseSet.Dictionary["Username"]);
            }
            if (apiResponseSet.Dictionary.ContainsKey("Password")) {
                credentials.Add("Password", apiResponseSet.Dictionary["Password"]);
            }

        }
        return credentials;
    }

    public String getAuthCredentials(String contextId, String userId) {
            return clientApi.users.getAuthenticationCredentials(contextId, userId).ToString();
    }

    /**
     * Creates a new {@link User} for a given context and returns the user id.
     *
     * @param contextId Id of a context.
     * @param name      Name of the user.
     * @return User id.
     * @throws ProxyException
     */
    public String newUser(String contextId, String name) {
            return ((ApiResponseElement) clientApi.users.newUser(this.apiKey, contextId, name)).Value;
    }

    /**
     * Removes a {@link User} using the given context id and user id.
     *
     * @param contextId Id of a {@link net.continuumsecurity.proxy.model.Context}
     * @param userId    Id of a {@link User}
     * @throws ProxyException
     */
    public void removeUser(String contextId, String userId) {
            clientApi.users.removeUser(this.apiKey, contextId, userId);
    }

    /**
     * Sets the authCredentialsConfigParams to the given context and user.
     * Bu default, authCredentialsConfigParams uses key value separator "=" and key value pair separator "&".
     * Make sure that values provided for authCredentialsConfigParams are URL encoded using "UTF-8".
     *
     * @param contextId                   Id of the context.
     * @param userId                      Id of the user.
     * @param authCredentialsConfigParams Authentication credentials config parameters.
     * @throws ProxyException
     */
    public void setAuthenticationCredentials(String contextId, String userId,
                                             String authCredentialsConfigParams) {
            clientApi.users.setAuthenticationCredentials(this.apiKey, contextId, userId,
                    authCredentialsConfigParams);
    }

    /**
     * Enables a {@link User} for a given {@link net.continuumsecurity.proxy.model.Context} id and user id.
     *
     * @param contextId Id of a {@link net.continuumsecurity.proxy.model.Context}
     * @param userId    Id of a {@link User}
     * @param enabled   Boolean value to enable/disable the user.
     * @throws ProxyException
     */
    public void setUserEnabled(String contextId, String userId, bool enabled)
    {
            clientApi.users.setUserEnabled(this.apiKey, contextId, userId, enabled.ToString());
    }

    /**
     * Sets a name to the user for the given context id and user id.
     *
     * @param contextId Id of a {@link net.continuumsecurity.proxy.model.Context}
     * @param userId    Id of a {@link User}
     * @param name      User name.
     * @throws ProxyException
     */
    public void setUserName(String contextId, String userId, String name){
            clientApi.users.setUserName(this.apiKey, contextId, userId, name);
    }

    /**
     * Returns the forced user id for a given context.
     *
     * @param contextId Id of a context.
     * @return Id of a forced {@link User}
     * @throws ProxyException
     */
    public String getForcedUserId(String contextId){
            return ((ApiResponseElement) clientApi.forcedUser.getForcedUser(contextId)).Value;
    }

    /**
     * Returns true if forced user mode is enabled. Otherwise returns false.
     *
     * @return true if forced user mode is enabled.
     * @throws ProxyException
     */
    public bool isForcedUserModeEnabled(){
            return Boolean.Parse(
                    ((ApiResponseElement) clientApi.forcedUser.isForcedUserModeEnabled()).Value);
    }

    /**
     * Enables/disables the forced user mode.
     *
     * @param forcedUserModeEnabled flag to enable/disable forced user mode.
     * @throws ProxyException
     */
    public void setForcedUserModeEnabled(bool forcedUserModeEnabled) {
            clientApi.forcedUser.setForcedUserModeEnabled(apiKey, forcedUserModeEnabled);
    }

    /**
     * Sets a {@link User} id as forced user for the given {@link net.continuumsecurity.proxy.model.Context}
     *
     * @param contextId Id of a context.
     * @param userId    Id of a user.
     * @throws ProxyException
     */
    public void setForcedUser(String contextId, String userId) {
            clientApi.forcedUser.setForcedUser(this.apiKey, contextId, userId);
    }

    /**
     * Returns list of supported session management methods.
     *
     * @return List of supported session management methods.
     * @throws ProxyException
     */
    public List<String> getSupportedSessionManagementMethods() {
        ApiResponseList apiResponseList = null;
            apiResponseList = (ApiResponseList) clientApi.sessionManagement
                    .getSupportedSessionManagementMethods();
        List<String> supportedSessionManagementMethods = new List<String>();
        foreach (IApiResponse apiResponse in apiResponseList.List) {
            supportedSessionManagementMethods.Add(((ApiResponseElement) apiResponse).Value);
        }
        return supportedSessionManagementMethods;
    }

    /**
     * Returns session management method selected for the given context.
     *
     * @param contextId Id of a context.
     * @return Session management method for a given context.
     * @throws ProxyException
     */
    public String getSessionManagementMethod(String contextId){
            return ((ApiResponseElement) clientApi.sessionManagement
                    .getSessionManagementMethod(contextId)).Value;
    }

    /**
     * Sets the given session management method and config params for a given context.
     *
     * @param contextId                   Id of a context.
     * @param sessionManagementMethodName Session management method name.
     * @param methodConfigParams          Session management method config parameters.
     * @throws ProxyException
     */
    public void setSessionManagementMethod(String contextId, String sessionManagementMethodName,
                                           String methodConfigParams){
            clientApi.sessionManagement
                    .setSessionManagementMethod(this.apiKey, contextId, sessionManagementMethodName,
                            methodConfigParams);
    }

    /**
     * Returns the list of Anti CSRF token names.
     *
     * @return List of Anti CSRF token names.
     * @throws ProxyException
     */
    public List<String> getAntiCsrfTokenNames() {
        String rawResponse;
            rawResponse = ((ApiResponseElement) clientApi.acsrf.optionTokensNames()).Value;
        return (rawResponse.Substring(1, rawResponse.Length - 1).Split(", ".ToCharArray())).ToList();
    }

    /**
     * Adds an anti CSRF token with the given name, enabled by default.
     *
     * @param tokenName Anti CSRF token name.
     * @throws ProxyException
     */
    public void addAntiCsrfToken(String tokenName){
            clientApi.acsrf.addOptionToken(apiKey, tokenName);
    }

    /**
     * Removes the anti CSRF token with the given name.
     *
     * @param tokenName Anti CSRF token name.
     * @throws ProxyException
     */
    public void removeAntiCsrfToken(String tokenName) {
            clientApi.acsrf.removeOptionToken(this.apiKey, tokenName);
    }

    /**
     * Returns the list of scripting engines that ZAP supports.
     *
     * @return List of script engines.
     * @throws ProxyException
     */
    public List<String> listEngines() {
        List<String> engines = new List<String>();
            ApiResponseList apiResponseList = (ApiResponseList) clientApi.script.listEngines();
            foreach(IApiResponse apiResponse in apiResponseList.List) {
                engines.Add(((ApiResponseElement) apiResponse).Value);
            }
        return engines;
    }

    /**
     * Returns the list of scripts loaded into ZAP.
     *
     * @return List of scripts.
     * @throws ProxyException
     */
    public List<Script> listScripts(){
        ApiResponseList apiResponseList=(ApiResponseList) clientApi.script.listScripts();
        List<Script> scripts = new List<Script>();
        if (apiResponseList != null) {
            foreach(IApiResponse apiResponse in apiResponseList.List) {
                scripts.Add(new Script((ApiResponseSet) apiResponse));
            }
        }
        return scripts;
    }

    /**
     * Disables the script, if the script name is a valid one.
     *
     * @param scriptName Name of the script.
     * @throws ProxyException
     */
    public void disableScript(String scriptName){
            clientApi.script.disable(this.apiKey, scriptName);
    }

    /**
     * Enables the script, if the script name is a valid one.
     *
     * @param scriptName Name of the script.
     * @throws ProxyException
     */
    public void enableScript(String scriptName) {
            clientApi.script.enable(this.apiKey, scriptName);
    }

    /**
     * Loads a script into ZAP session.
     *
     * @param scriptName   Name of the script.
     * @param scriptType   Type of the script such as authentication, httpsender, etc.
     * @param scriptEngine Script engine such as Rhino, Mozilla Zest, etc.
     * @param fileName     Name of the file including the full path.
     * @throws ProxyException
     */
    public void loadScript(String scriptName, String scriptType, String scriptEngine,
                           String fileName) {
        loadScript(scriptName, scriptType, scriptEngine, fileName, "");
    }

    /**
     * Loads a script into ZAP session.
     *
     * @param scriptName        Name of the script.
     * @param scriptType        Type of the script such as authentication, httpsender, etc.
     * @param scriptEngine      Script engine such Rhino, Mozilla Zest, etc.
     * @param fileName          Name of the file including the full path.
     * @param scriptDescription Script description.
     * @throws ProxyException
     */
    public void loadScript(String scriptName, String scriptType, String scriptEngine,
                           String fileName, String scriptDescription) {
            clientApi.script
                    .load(this.apiKey, scriptName, scriptType, scriptEngine, fileName, scriptDescription);
    }

    /**
     * Removes the script with given name.
     *
     * @param scriptName Name of the script.
     * @throws ProxyException
     */
    public void removeScript(String scriptName) {
            clientApi.script.remove(this.apiKey, scriptName);
    }

    /**
     * Runs a stand alone script with the given name.
     *
     * @param scriptName Name of the script.
     * @throws ProxyException
     */
    public void runStandAloneScript(String scriptName){
            clientApi.script.runStandAloneScript(this.apiKey, scriptName);
    }

    public void setIncludeInContext(String contextName, String regex) {

            IApiResponse response = clientApi.context.includeInContext(this.apiKey, contextName, regex);
            //TODO: add does not exist error handling
            //if ("does_not_exist".equalsIgnoreCase(e.getCode())) {
            //    createContext(contextName);
            //    setIncludeInContext(contextName, regex);
            //} 
        
    }

    private void createContext(String contextName) {
            clientApi.context.newContext(this.apiKey, contextName);
    }

    private static class ClientApiUtils {

        public static int getInteger(IApiResponse response) {
                return Int32.Parse(((ApiResponseElement) response).Value);
        }

        public static String convertHarRequestToString(HarSharp.Request request) {
            return JsonConvert.SerializeObject(request);
        }

        public static HarSharp.Log createHarLog(byte[] bytesHarLog) {
            if(bytesHarLog.Length == 0) {
                throw new SystemException("Unexpected ZAP response.");
            }
            return HarSharp.HarConvert.Deserialize(Encoding.UTF8.GetString(bytesHarLog)).Log;
        }

        public static IList<HarSharp.Entry> getHarEntries(byte[] bytesHarLog) {
            return createHarLog(bytesHarLog).Entries;
        }

    }
    }
}
