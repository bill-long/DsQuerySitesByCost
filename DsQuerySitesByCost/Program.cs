using System;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using DWORD = System.UInt32;

namespace DsQuerySitesByCostTool
{
    class Program
    {
        #region AD methods and types
        [DllImport("NetApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern UInt32 DsGetSiteName([MarshalAs(UnmanagedType.LPTStr)]string ComputerName, out IntPtr SiteNameBuffer);

        // The following types are adapted from the Active Directory Utils project
        // at http://activedirectoryutils.codeplex.com/, with some minor corrections.
        // See the original definitions in Unsafe.NtDsAPI.cs in that project.

        [DllImport("Ntdsapi.dll", CharSet = CharSet.Auto, EntryPoint = "DsUnBind", SetLastError = false, ThrowOnUnmappableChar = true), SuppressUnmanagedCodeSecurity]
        static private extern DWORD DsUnBind(
            IntPtr phDS);

        [SuppressUnmanagedCodeSecurity, ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public class DsHandle : SafeHandle
        {
            public DsHandle()
                : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid
            {
                get { return this.IsClosed || handle == IntPtr.Zero; }
            }

            [SuppressUnmanagedCodeSecurity, ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            protected override bool ReleaseHandle()
            {
                DWORD ret = DsUnBind(handle);
                System.Diagnostics.Debug.WriteLineIf(ret != 0, "Error unbinding :\t" + ret.ToString());
                return ret == 0;
            }
        }

        [DllImport("Ntdsapi.dll", CharSet = CharSet.Auto, EntryPoint = "DsBindToISTG", SetLastError = false, ThrowOnUnmappableChar = true), SuppressUnmanagedCodeSecurity]
        static public extern DWORD DsBindToISTG(
            [MarshalAs(UnmanagedType.LPWStr)] string SiteName
            , out DsHandle phDS);

        [StructLayout(LayoutKind.Sequential)]
        public struct DS_SITE_COST_INFO
        {
            public DWORD errorCode;
            public DWORD cost;
        }

        [DllImport("Ntdsapi.dll", CharSet = CharSet.Auto, EntryPoint = "DsQuerySitesByCost", SetLastError = false, ThrowOnUnmappableChar = true), SuppressUnmanagedCodeSecurity]
        static public extern DWORD DsQuerySitesByCost(
            DsHandle hDs
            , [MarshalAs(UnmanagedType.LPWStr)] string pwszFromSite
            , [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] rgwszToSites
            , DWORD cToSites
            , DWORD dwFlags
            , out IntPtr prgSiteInfo);

        //
        // End of Active Directory Utils types.
        //
        #endregion

        private static void Main(string[] args)
        {
            DsHandle istgHandle;
            var bindresult = DsBindToISTG(null, out istgHandle);
            if (bindresult != 0)
            {
                Console.WriteLine("DsBindToISTG failed with code: " + bindresult);
                return;
            }

            IntPtr siteNameBuffer;
            var getSiteResult = DsGetSiteName(null, out siteNameBuffer);
            if (getSiteResult != 0)
            {
                Console.WriteLine("DsGetSiteName failed with code: " + getSiteResult);
                return;
            }

            var localSiteName = Marshal.PtrToStringAuto(siteNameBuffer);
            Console.WriteLine();
            Console.WriteLine("Local site name: " + localSiteName);

            string[] sites;
            if (args.Length > 0)
            {
                sites = args;
            }
            else
            {
                sites = GetAllSiteNames();
                Console.WriteLine("Found " + sites.Length + " sites.");
            }

            IntPtr costInfoPtr;
            var queryResult = DsQuerySitesByCost(istgHandle, localSiteName, sites, (uint) sites.Length,
                0,
                out costInfoPtr);
            if (queryResult != 0 || costInfoPtr == IntPtr.Zero)
            {
                Console.WriteLine("DsQuerySitesByCost failed with code: " + queryResult);
                return;
            }

            var costInfoArray = new DS_SITE_COST_INFO[sites.Length];
            for (var x = 0; x < costInfoArray.Length; x++)
            {
                costInfoArray[x] = (DS_SITE_COST_INFO)Marshal.PtrToStructure((IntPtr) ((long)costInfoPtr + (Marshal.SizeOf(typeof(DS_SITE_COST_INFO))*x)), typeof(DS_SITE_COST_INFO));
            }

            var columnSize = sites.Max(a => a.Length);
            if (columnSize < 9) columnSize = 9;
            columnSize += 5;
            Console.WriteLine();
            WriteWithPadding("Site Name", "Cost", columnSize);
            for (var x = 0; x < costInfoArray.Length; x++)
            {
                if (costInfoArray[x].errorCode != 0)
                {
                    WriteWithPadding(sites[x], "Error: " + costInfoArray[x].errorCode, columnSize);
                }
                else
                {
                    WriteWithPadding(sites[x], costInfoArray[x].cost.ToString(), columnSize);
                }
            }
        }

        private static void WriteWithPadding(string firstColumn, string secondColumn, int firstColumnSize)
        {
            var padding = firstColumnSize - firstColumn.Length;
            Console.Write(firstColumn);
            for (var x = 0; x < padding; x++) Console.Write(" ");
            Console.WriteLine(secondColumn);
        }

        private static string[] GetAllSiteNames()
        {
            var rootDSE = new DirectoryEntry("LDAP://RootDSE");
            var configNC = new DirectoryEntry("LDAP://" + rootDSE.Properties["configurationNamingContext"][0]);
            var sitesContainer = new DirectoryEntry("LDAP://CN=Sites," + configNC.Properties["distinguishedName"][0]);
            var siteFinder = new DirectorySearcher(sitesContainer, "(objectClass=site)");
            siteFinder.PageSize = 100;
            var results = siteFinder.FindAll();
            var siteNames = new string[results.Count];
            for (var x = 0; x < results.Count; x++)
            {
                siteNames[x] = results[x].Properties["name"][0].ToString();
            }

            return siteNames;
        }
    }
}
