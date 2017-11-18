using OWASPZAPDotNetAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZapCSharpAPI
{
public class ScanInfo : IComparable<ScanInfo> {
    
    public int CompareTo(ScanInfo o) {
        return Id-o.Id;
    }

    public enum State {
        NOT_STARTED,
        FINISHED,
        PAUSED,
        RUNNING
    }

    public static State ParseState(String s) {
        if ("NOT_STARTED".Equals(s)) return State.NOT_STARTED;
        if ("FINISHED".Equals(s)) return State.FINISHED;
        if ("PAUSED".Equals(s)) return State.PAUSED;
        if ("RUNNING".Equals(s)) return State.RUNNING;
        throw new SystemException("Unknown state: "+s);
    }

    public ScanInfo(ApiResponseSet response) {
        Id = Int32.Parse(response.Dictionary["id"]);
        Progress = Int32.Parse(response.Dictionary["progress"]);
        ScanState = ParseState(response.Dictionary["state"]);
    }

    public int Progress {get; set;}

    public int Id {get; set;}

    public State ScanState {get; set;}
}
}
