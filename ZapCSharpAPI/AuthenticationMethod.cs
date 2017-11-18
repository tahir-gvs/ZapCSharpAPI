using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZapCSharpAPI
{
/**
 * Authentication methods supported by ZAP.
 */
public class AuthenticationMethod {
    public static readonly AuthenticationMethod FORM_BASED_AUTHENTICATION = new AuthenticationMethod("formBasedAuthentication");
    public static readonly AuthenticationMethod HTTP_AUTHENTICATION = new AuthenticationMethod("httpAuthentication");
    public static readonly AuthenticationMethod MANUAL_AUTHENTICATION = new AuthenticationMethod("manualAuthentication");
    public static readonly AuthenticationMethod SCRIPT_BASED_AUTHENTICATION = new AuthenticationMethod("scriptBasedAuthentication");
    private static List<AuthenticationMethod> enumValues = new List<AuthenticationMethod>();
    private String value;

    public String getValue() {
        return value;
    }

    private AuthenticationMethod(String authenticationMethod) {
        this.value = authenticationMethod;
        enumValues.Add(this);
    }

    public static List<String> getValues() {
        List<String> values = new List<String>();
        foreach (AuthenticationMethod authenticationMethod in AuthenticationMethod.enumValues)
        {
            values.Add(authenticationMethod.getValue());
        }
        return values;
    }
}
}
