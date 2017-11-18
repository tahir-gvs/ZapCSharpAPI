using OWASPZAPDotNetAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZapCSharpAPI
{
    public class ScanResponse
    {
        List<ScanInfo> scans = new List<ScanInfo>();

        public ScanResponse(ApiResponseList responseList) {
        foreach (IApiResponse rawResponse in responseList.List) {
            scans.Add(new ScanInfo((ApiResponseSet)rawResponse));
        }
        scans.Sort();
    }

        public List<ScanInfo> getScans()
        {
            return scans;
        }

        public ScanInfo getScanById(int scanId) {
        foreach (ScanInfo scan in scans) {
            if (scan.Id == scanId) return scan;
        }
        return null;
    }

        public ScanInfo getLastScan()
        {
            if (scans.Count == 0) throw new SystemException("No scans found");
            return scans[scans.Count - 1];
        }
    }
}
