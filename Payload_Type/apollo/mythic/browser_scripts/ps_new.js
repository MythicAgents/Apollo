function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        let file = {};
        let data = "";
        let rows = [];
        let headers = [
            {"plaintext": "ppid", "type": "number", "copyIcon": true, "cellStyle": {}, "width": 100},
            {"plaintext": "pid", "type": "number", "copyIcon": true, "cellStyle": {}, "width": 100},
            {"plaintext": "arch", "type": "string", "cellStyle": {}, "width": 100},
            {"plaintext": "name", "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "user", "type": "string", "cellStyle": {}, "fillWidth": 250},
            {"plaintext": "session", "type": "number", "cellStyle": {}, "width": 100},
            {"plaintext": "signer", "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "actions", "type": "button", "cellStyle": {}, "width": 100, "disableSort": true},
        ];
        for(let i = 0; i < responses.length; i++)
        {
            try{
                data = JSON.parse(responses[i]);
            }catch(error){
                console.log(error);
               const combined = responses.reduce( (prev, cur) => {
                    return prev + cur;
                }, "");
                return {'plaintext': combined};
            }
            let avProcesses = ["Tanium", "360RP", "360SD", "360Safe", "360leakfixer", "360rp", "360safe", "360sd", "360tray", "AAWTray", "ACAAS", "ACAEGMgr", "ACAIS", "AClntUsr", "ALERT", "ALERTSVC", "ALMon", "ALUNotify", "ALUpdate", "ALsvc", "AVENGINE", "AVGCHSVX", "AVGCSRVX", "AVGIDSAgent", "AVGIDSMonitor", "AVGIDSUI", "AVGIDSWatcher", "AVGNSX", "AVKProxy", "AVKService", "AVKTray", "AVKWCtl", "AVP", "AVP", "AVPDTAgt", "AcctMgr", "Ad-Aware", "Ad-Aware2007", "AddressExport", "AdminServer", "Administrator", "AeXAgentUIHost", "AeXNSAgent", "AeXNSRcvSvc", "AlertSvc", "AlogServ", "AluSchedulerSvc", "AnVir", "AppSvc32", "AtrsHost", "Auth8021x", "AvastSvc", "AvastUI", "Avconsol", "AvpM", "Avsynmgr", "Avtask", "BLACKD", "BWMeterConSvc", "CAAntiSpyware", "CALogDump", "CAPPActiveProtection", "CAPPActiveProtection", "CB", "CCAP", "CCenter", "CClaw", "CLPS", "CLPSLA", "CLPSLS", "CNTAoSMgr", "CPntSrv", "CTDataLoad", "CertificationManagerServiceNT", "ClShield", "ClamTray", "ClamWin", "Console", "CylanceUI", "DAO_Log", "DLService", "DLTray", "DLTray", "DRWAGNTD", "DRWAGNUI", "DRWEB32W", "DRWEBSCD", "DRWEBUPW", "DRWINST", "DSMain", "DWHWizrd", "DefWatch", "DolphinCharge", "EHttpSrv", "EMET_Agent", "EMET_Service", "EMLPROUI", "EMLPROXY", "EMLibUpdateAgentNT", "ETConsole3", "ETCorrel", "ETLogAnalyzer", "ETReporter", "ETRssFeeds", "EUQMonitor", "EndPointSecurity", "EngineServer", "EntityMain", "EtScheduler", "EtwControlPanel", "EventParser", "FAMEH32", "FCDBLog", "FCH32", "FPAVServer", "FProtTray", "FSCUIF", "FSHDLL32", "FSM32", "FSMA32", "FSMB32", "FWCfg", "FireSvc", "FireTray", "FirewallGUI", "ForceField", "FortiProxy", "FortiTray", "FortiWF", "FrameworkService", "FreeProxy", "GDFirewallTray", "GDFwSvc", "HWAPI", "ISNTSysMonitor", "ISSVC", "ISWMGR", "ITMRTSVC", "ITMRT_SupportDiagnostics", "ITMRT_TRACE", "IcePack", "IdsInst", "InoNmSrv", "InoRT", "InoRpc", "InoTask", "InoWeb", "IsntSmtp", "KABackReport", "KANMCMain", "KAVFS", "KAVStart", "KLNAGENT", "KMailMon", "KNUpdateMain", "KPFWSvc", "KSWebShield", "KVMonXP", "KVMonXP_2", "KVSrvXP", "KWSProd", "KWatch", "KavAdapterExe", "KeyPass", "KvXP", "LUALL", "LWDMServer", "LockApp", "LockAppHost", "LogGetor", "MCSHIELD", "MCUI32", "MSASCui", "ManagementAgentNT", "McAfeeDataBackup", "McEPOC", "McEPOCfg", "McNASvc", "McProxy", "McScript_InUse", "McWCE", "McWCECfg", "Mcshield", "Mctray", "MgntSvc", "MpCmdRun", "MpfAgent", "MpfSrv", "MsMpEng", "NAIlgpip", "NAVAPSVC", "NAVAPW32", "NCDaemon", "NIP", "NJeeves", "NLClient", "NMAGENT", "NOD32view", "NPFMSG", "NPROTECT", "NRMENCTB", "NSMdtr", "NTRtScan", "NVCOAS", "NVCSched", "NavShcom", "Navapsvc", "NaveCtrl", "NaveLog", "NaveSP", "Navw32", "Navwnt", "Nip", "Njeeves", "Npfmsg2", "Npfsvice", "NscTop", "Nvcoas", "Nvcsched", "Nymse", "OLFSNT40", "OMSLogManager", "ONLINENT", "ONLNSVC", "OfcPfwSvc", "PASystemTray", "PAVFNSVR", "PAVSRV51", "PNmSrv", "POPROXY", "POProxy", "PPClean", "PPCtlPriv", "PQIBrowser", "PSHost", "PSIMSVC", "PXEMTFTP", "PadFSvr", "Pagent", "Pagentwd", "PavBckPT", "PavFnSvr", "PavPrSrv", "PavProt", "PavReport", "Pavkre", "PcCtlCom", "PcScnSrv", "PccNTMon", "PccNTUpd", "PpPpWallRun", "PrintDevice", "ProUtil", "PsCtrlS", "PsImSvc", "PwdFiltHelp", "Qoeloader", "RAVMOND", "RAVXP", "RNReport", "RPCServ", "RSSensor", "RTVscan", "RapApp", "Rav", "RavAlert", "RavMon", "RavMonD", "RavService", "RavStub", "RavTask", "RavTray", "RavUpdate", "RavXP", "RealMon", "Realmon", "RedirSvc", "RegMech", "ReporterSvc", "RouterNT", "Rtvscan", "SAFeService", "SAService", "SAVAdminService", "SAVFMSESp", "SAVMain", "SAVScan", "SCANMSG", "SCANWSCS", "SCFManager", "SCFService", "SCFTray", "SDTrayApp", "SEVINST", "SMEX_ActiveUpdate", "SMEX_Master", "SMEX_RemoteConf", "SMEX_SystemWatch", "SMSECtrl", "SMSELog", "SMSESJM", "SMSESp", "SMSESrv", "SMSETask", "SMSEUI", "SNAC", "SNAC", "SNDMon", "SNDSrvc", "SPBBCSvc", "SPIDERML", "SPIDERNT", "SSM", "SSScheduler", "SVCharge", "SVDealer", "SVFrame", "SVTray", "SWNETSUP", "SavRoam", "SavService", "SavUI", "ScanMailOutLook", "SeAnalyzerTool", "SemSvc", "SescLU", "SetupGUIMngr", "SiteAdv", "Smc", "SmcGui", "SnHwSrv", "SnICheckAdm", "SnIcon", "SnSrv", "SnicheckSrv", "SpIDerAgent", "SpntSvc", "SpyEmergency", "SpyEmergencySrv", "StOPP", "StWatchDog", "SymCorpUI", "SymSPort", "TBMon", "TFGui", "TFService", "TFTray", "TFun", "TIASPN~1", "TSAnSrf", "TSAtiSy", "TScutyNT", "TSmpNT", "TmListen", "TmPfw", "Tmntsrv", "Traflnsp", "TrapTrackerMgr", "UPSCHD", "UcService", "UdaterUI", "UmxAgent", "UmxCfg", "UmxFwHlp", "UmxPol", "Up2date", "UpdaterUI", "UrlLstCk", "UserActivity", "UserAnalysis", "UsrPrmpt", "V3Medic", "V3Svc", "VPC32", "VPDN_LU", "VPTray", "VSStat", "VsStat", "VsTskMgr", "WEBPROXY", "WFXCTL32", "WFXMOD32", "WFXSNT40", "WebProxy", "WebScanX", "WinRoute", "WrSpySetup", "ZLH", "Zanda", "ZhuDongFangYu", "Zlh", "_avp32", "_avpcc", "_avpm", "aAvgApi", "aawservice", "acaif", "acctmgr", "ackwin32", "aclient", "adaware", "advxdwin", "aexnsagent", "aexsvc", "aexswdusr", "aflogvw", "afwServ", "agentsvr", "agentw", "ahnrpt", "ahnsd", "ahnsdsv", "alertsvc", "alevir", "alogserv", "alsvc", "alunotify", "aluschedulersvc", "amon9x", "amswmagt", "anti-trojan", "antiarp", "antivirus", "ants", "aphost", "apimonitor", "aplica32", "aps", "apvxdwin", "arr", "ashAvast", "ashBug", "ashChest", "ashCmd", "ashDisp", "ashEnhcd", "ashLogV", "ashMaiSv", "ashPopWz", "ashQuick", "ashServ", "ashSimp2", "ashSimpl", "ashSkPcc", "ashSkPck", "ashUpd", "ashWebSv", "ashdisp", "ashmaisv", "ashserv", "ashwebsv", "asupport", "aswDisp", "aswRegSvr", "aswServ", "aswUpdSv", "aswUpdsv", "aswWebSv", "aswupdsv", "atcon", "atguard", "atro55en", "atupdater", "atwatch", "atwsctsk", "au", "aupdate", "aupdrun", "aus", "auto-protect.nav80try", "autodown", "autotrace", "autoup", "autoupdate", "avEngine", "avadmin", "avcenter", "avconfig", "avconsol", "ave32", "avengine", "avesvc", "avfwsvc", "avgam", "avgamsvr", "avgas", "avgcc", "avgcc32", "avgcsrvx", "avgctrl", "avgdiag", "avgemc", "avgfws8", "avgfws9", "avgfwsrv", "avginet", "avgmsvr", "avgnsx", "avgnt", "avgregcl", "avgrssvc", "avgrsx", "avgscanx", "avgserv", "avgserv9", "avgsystx", "avgtray", "avguard", "avgui", "avgupd", "avgupdln", "avgupsvc", "avgvv", "avgw", "avgwb", "avgwdsvc", "avgwizfw", "avkpop", "avkserv", "avkservice", "avkwctl9", "avltmain", "avmailc", "avmcdlg", "avnotify", "avnt", "avp", "avp32", "avpcc", "avpdos32", "avpexec", "avpm", "avpncc", "avps", "avptc32", "avpupd", "avscan", "avsched32", "avserver", "avshadow", "avsynmgr", "avwebgrd", "avwin", "avwin95", "avwinnt", "avwupd", "avwupd32", "avwupsrv", "avxmonitor9x", "avxmonitornt", "avxquar", "backweb", "bargains", "basfipm", "bd_professional", "bdagent", "bdc", "bdlite", "bdmcon", "bdss", "bdsubmit", "beagle", "belt", "bidef", "bidserver", "bipcp", "bipcpevalsetup", "bisp", "blackd", "blackice", "blink", "blss", "bmrt", "bootconf", "bootwarn", "borg2", "bpc", "bpk", "brasil", "bs120", "bundle", "bvt", "bwgo0000", "ca", "caav", "caavcmdscan", "caavguiscan", "caf", "cafw", "caissdt", "capfaem", "capfasem", "capfsem", "capmuamagt", "casc", "casecuritycenter", "caunst", "cavrep", "cavrid", "cavscan", "cavtray", "ccApp", "ccEvtMgr", "ccLgView", "ccProxy", "ccSetMgr", "ccSetmgr", "ccSvcHst", "ccap", "ccapp", "ccevtmgr", "cclaw", "ccnfagent", "ccprovsp", "ccproxy", "ccpxysvc", "ccschedulersvc", "ccsetmgr", "ccsmagtd", "ccsvchst", "ccsystemreport", "cctray", "ccupdate", "cdp", "cfd", "cfftplugin", "cfgwiz", "cfiadmin", "cfiaudit", "cfinet", "cfinet32", "cfnotsrvd", "cfp", "cfpconfg", "cfpconfig", "cfplogvw", "cfpsbmit", "cfpupdat", "cfsmsmd", "checkup", "cka", "clamscan", "claw95", "claw95cf", "clean", "cleaner", "cleaner3", "cleanpc", "cleanup", "click", "cmdagent", "cmdinstall", "cmesys", "cmgrdian", "cmon016", "comHost", "connectionmonitor", "control_panel", "cpd", "cpdclnt", "cpf", "cpf9x206", "cpfnt206", "crashrep", "csacontrol", "csinject", "csinsm32", "csinsmnt", "csrss_tc", "ctrl", "cv", "cwnb181", "cwntdwmo", "cz", "datemanager", "dbserv", "dbsrv9", "dcomx", "defalert", "defscangui", "defwatch", "deloeminfs", "deputy", "diskmon", "divx", "djsnetcn", "dllcache", "dllreg", "doors", "doscan", "dpf", "dpfsetup", "dpps2", "drwagntd", "drwatson", "drweb", "drweb32", "drweb32w", "drweb386", "drwebcgp", "drwebcom", "drwebdc", "drwebmng", "drwebscd", "drwebupw", "drwebwcl", "drwebwin", "drwupgrade", "dsmain", "dssagent", "dvp95", "dvp95_0", "dwengine", "dwhwizrd", "dwwin", "ecengine", "edisk", "efpeadm", "egui", "ekrn", "elogsvc", "emet_agent", "emet_service", "emsw", "engineserver", "ent", "era", "esafe", "escanhnt", "escanv95", "esecagntservice", "esecservice", "esmagent", "espwatch", "etagent", "ethereal", "etrustcipe", "evpn", "evtProcessEcFile", "evtarmgr", "evtmgr", "exantivirus-cnet", "exe.avxw", "execstat", "expert", "explore", "f-agnt95", "f-prot", "f-prot95", "f-stopw", "fameh32", "fast", "fch32", "fih32", "findviru", "firesvc", "firetray", "firewall", "fmon", "fnrb32", "fortifw", "fp-win", "fp-win_trial", "fprot", "frameworkservice", "frminst", "frw", "fsaa", "fsaua", "fsav", "fsav32", "fsav530stbyb", "fsav530wtbyb", "fsav95", "fsavgui", "fscuif", "fsdfwd", "fsgk32", "fsgk32st", "fsguidll", "fsguiexe", "fshdll32", "fsm32", "fsma32", "fsmb32", "fsorsp", "fspc", "fspex", "fsqh", "fssm32", "fwinst", "gator", "gbmenu", "gbpoll", "gcascleaner", "gcasdtserv", "gcasinstallhelper", "gcasnotice", "gcasserv", "gcasservalert", "gcasswupdater", "generics", "gfireporterservice", "ghost_2", "ghosttray", "giantantispywaremain", "giantantispywareupdater", "gmt", "guard", "guarddog", "guardgui", "hacktracersetup", "hbinst", "hbsrv", "hipsvc", "hotactio", "hotpatch", "htlog", "htpatch", "hwpe", "hxdl", "hxiul", "iamapp", "iamserv", "iamstats", "ibmasn", "ibmavsp", "icepack", "icload95", "icloadnt", "icmon", "icsupp95", "icsuppnt", "idle", "iedll", "iedriver", "iface", "ifw2000", "igateway", "inetlnfo", "infus", "infwin", "inicio", "init", "inonmsrv", "inorpc", "inort", "inotask", "intdel", "intren", "iomon98", "isPwdSvc", "isUAC", "isafe", "isafinst", "issvc", "istsvc", "jammer", "jdbgmrg", "jedi", "kaccore", "kansgui", "kansvr", "kastray", "kav", "kav32", "kavfs", "kavfsgt", "kavfsrcn", "kavfsscs", "kavfswp", "kavisarv", "kavlite40eng", "kavlotsingleton", "kavmm", "kavpers40eng", "kavpf", "kavshell", "kavss", "kavstart", "kavsvc", "kavtray", "kazza", "keenvalue", "kerio-pf-213-en-win", "kerio-wrl-421-en-win", "kerio-wrp-421-en-win", "kernel32", "killprocesssetup161", "kis", "kislive", "kissvc", "klnacserver", "klnagent", "klserver", "klswd", "klwtblfs", "kmailmon", "knownsvr", "kpf4gui", "kpf4ss", "kpfw32", "kpfwsvc", "krbcc32s", "kvdetech", "kvolself", "kvsrvxp", "kvsrvxp_1", "kwatch", "kwsprod", "kxeserv", "launcher", "ldnetmon", "ldpro", "ldpromenu", "ldscan", "leventmgr", "livesrv", "lmon", "lnetinfo", "loader", "localnet", "lockdown", "lockdown2000", "log_qtine", "lookout", "lordpe", "lsetup", "luall", "luau", "lucallbackproxy", "lucoms", "lucomserver", "lucoms~1", "luinit", "luspt", "makereport", "mantispm", "mapisvc32", "masalert", "massrv", "mcafeefire", "mcagent", "mcappins", "mcconsol", "mcdash", "mcdetect", "mcepoc", "mcepocfg", "mcinfo", "mcmnhdlr", "mcmscsvc", "mcods", "mcpalmcfg", "mcpromgr", "mcregwiz", "mcscript", "mcscript_inuse", "mcshell", "mcshield", "mcshld9x", "mcsysmon", "mctool", "mctray", "mctskshd", "mcuimgr", "mcupdate", "mcupdmgr", "mcvsftsn", "mcvsrte", "mcvsshld", "mcwce", "mcwcecfg", "md", "mfeann", "mfevtps", "mfin32", "mfw2en", "mfweng3.02d30", "mgavrtcl", "mgavrte", "mghtml", "mgui", "minilog", "mmod", "monitor", "monsvcnt", "monsysnt", "moolive", "mostat", "mpcmdrun", "mpf", "mpfagent", "mpfconsole", "mpfservice", "mpftray", "mps", "mpsevh", "mpsvc", "mrf", "mrflux", "msapp", "msascui", "msbb", "msblast", "mscache", "msccn32", "mscifapp", "mscman", "msconfig", "msdm", "msdos", "msiexec16", "mskagent", "mskdetct", "msksrver", "msksrvr", "mslaugh", "msmgt", "msmpeng", "msmsgri32", "msscli", "msseces", "mssmmc32", "msssrv", "mssys", "msvxd", "mu0311ad", "mwatch", "myagttry", "n32scanw", "nSMDemf", "nSMDmon", "nSMDreal", "nSMDsch", "naPrdMgr", "nav", "navap.navapsvc", "navapsvc", "navapw32", "navdx", "navlu32", "navnt", "navstub", "navw32", "navwnt", "nc2000", "ncinst4", "MSASCuiL", "MBAMService", "mbamtray", "CylanceSvc", "ndd32", "ndetect", "neomonitor", "neotrace", "neowatchlog", "netalertclient", "netarmor", "netcfg", "netd32", "netinfo", "netmon", "netscanpro", "netspyhunter-1.2", "netstat", "netutils", "networx", "ngctw32", "ngserver", "nip", "nipsvc", "nisoptui", "nisserv", "nisum", "njeeves", "nlsvc", "nmain", "nod32", "nod32krn", "nod32kui", "normist", "norton_internet_secu_3.0_407", "notstart", "npf40_tw_98_nt_me_2k", "npfmessenger", "npfmntor", "npfmsg", "nprotect", "npscheck", "npssvc", "nrmenctb", "nsched32", "nscsrvce", "nsctop", "nsmdtr", "nssys32", "nstask32", "nsupdate", "nt", "ntcaagent", "ntcadaemon", "ntcaservice", "ntrtscan", "ntvdm", "ntxconfig", "nui", "nupgrade", "nvarch16", "nvc95", "nvcoas", "nvcsched", "nvsvc32", "nwinst4", "nwservice", "nwtool16", "nymse", "oasclnt", "oespamtest", "ofcdog", "ofcpfwsvc", "okclient", "olfsnt40", "ollydbg", "onsrvr", "op_viewer", "opscan", "optimize", "ostronet", "otfix", "outpost", "outpostinstall", "outpostproinstall", "paamsrv", "padmin", "pagent", "pagentwd", "panixk", "patch", "pavbckpt", "pavcl", "pavfires", "pavfnsvr", "pavjobs", "pavkre", "pavmail", "pavprot", "pavproxy", "pavprsrv", "pavsched", "pavsrv50", "pavsrv51", "pavsrv52", "pavupg", "pavw", "pccNT", "pccclient", "pccguide", "pcclient", "pccnt", "pccntmon", "pccntupd", "pccpfw", "pcctlcom", "pccwin98", "pcfwallicon", "pcip10117_0", "pcscan", "pctsAuxs", "pctsGui", "pctsSvc", "pctsTray", "pdsetup", "pep", "periscope", "persfw", "perswf", "pf2", "pfwadmin", "pgmonitr", "pingscan", "platin", "pmon", "pnmsrv", "pntiomon", "pop3pack", "pop3trap", "poproxy", "popscan", "portdetective", "portmonitor", "powerscan", "ppinupdt", "ppmcativedetection", "pptbc", "ppvstop", "pqibrowser", "pqv2isvc", "prevsrv", "prizesurfer", "prmt", "prmvr", "programauditor", "proport", "protectx", "psctris", "psh_svc", "psimreal", "psimsvc", "pskmssvc", "pspf", "purge", "pview", "pviewer", "pxemtftp", "pxeservice", "qclean", "qconsole", "qdcsfs", "qoeloader", "qserver", "rapapp", "rapuisvc", "ras", "rasupd", "rav7", "rav7win", "rav8win32eng", "ravmon", "ravmond", "ravstub", "ravxp", "ray", "rb32", "rcsvcmon", "rcsync", "realmon", "reged", "remupd", "reportsvc", "rescue", "rescue32", "rfwmain", "rfwproxy", "rfwsrv", "rfwstub", "rnav", "rrguard", "rshell", "rsnetsvr", "rstray", "rtvscan", "rtvscn95", "rulaunch", "saHookMain", "safeboxtray", "safeweb", "sahagentscan32", "sav32cli", "save", "savenow", "savroam", "savscan", "savservice", "sbserv", "scam32", "scan32", "scan95", "scanexplicit", "scanfrm", "scanmailoutlook", "scanpm", "schdsrvc", "schupd", "scrscan", "seestat", "serv95", "setloadorder", "setup_flowprotector_us", "setupguimngr", "setupvameeval", "sfc", "sgssfw32", "sh", "shellspyinstall", "shn", "showbehind", "shstat", "siteadv", "smOutlookPack", "smc", "smoutlookpack", "sms", "smsesp", "smss32", "sndmon", "sndsrvc", "soap", "sofi", "softManager", "spbbcsvc", "spf", "sphinx", "spideragent", "spiderml", "spidernt", "spiderui", "spntsvc", "spoler", "spoolcv", "spoolsv32", "spyxx", "srexe", "srng", "srvload", "srvmon", "ss3edit", "sschk", "ssg_4104", "ssgrate", "st2", "stcloader", "stinger", "stopp", "stwatchdog", "supftrl", "support", "supporter5", "svcGenericHost", "svcharge", "svchostc", "svchosts", "svcntaux", "svdealer", "svframe", "svtray", "swdsvc", "sweep95", "sweepnet.sweepsrv.sys.swnetsup", "sweepsrv", "swnetsup", "swnxt", "swserver", "symlcsvc", "symproxysvc", "symsport", "symtray", "symwsc", "sysdoc32", "sysedit", "sysupd", "taskmo", "taumon", "tbmon", "tbscan", "tc", "tca", "tclproc", "tcm", "tdimon", "tds-3", "tds2-98", "tds2-nt", "teekids", "tfak", "tfak5", "tgbob", "titanin", "titaninxp", "tmas", "tmlisten", "tmntsrv", "tmpfw", "tmproxy", "tnbutil", "tpsrv", "tracesweeper", "trickler", "trjscan", "trjsetup", "trojantrap3", "trupd", "tsadbot", "tvmd", "tvtmd", "udaterui", "undoboot", "unvet32", "updat", "updtnv28", "upfile", "upgrad", "uplive", "urllstck", "usergate", "usrprmpt", "utpost", "v2iconsole", "v3clnsrv", "v3exec", "v3imscn", "vbcmserv", "vbcons", "vbust", "vbwin9x", "vbwinntw", "vcsetup", "vet32", "vet95", "vetmsg", "vettray", "vfsetup", "vir-help", "virusmdpersonalfirewall", "vnlan300", "vnpc3000", "vpatch", "vpc32", "vpc42", "vpfw30s", "vprosvc", "vptray", "vrv", "vrvmail", "vrvmon", "vrvnet", "vscan40", "vscenu6.02d30", "vsched", "vsecomr", "vshwin32", "vsisetup", "vsmain", "vsmon", "vsserv", "vsstat", "vstskmgr", "vswin9xe", "vswinntse", "vswinperse", "w32dsm89", "w9x", "watchdog", "webdav", "webproxy", "webscanx", "webtrap", "webtrapnt", "wfindv32", "wfxctl32", "wfxmod32", "wfxsnt40", "whoswatchingme", "wimmun32", "win-bugsfix", "winactive", "winmain", "winnet", "winppr32", "winrecon", "winroute", "winservn", "winssk32", "winstart", "winstart001", "wintsk32", "winupdate", "wkufind", "wnad", "wnt", "wradmin", "wrctrl", "wsbgate", "wssfcmai", "wupdater", "wupdt", "wyvernworksfirewall", "xagt", "xagtnotif", "xcommsvr", "xfilter", "xpf202en", "zanda", "zapro", "zapsetup3001", "zatutor", "zhudongfangyu", "zlclient", "zlh", "zonalm2601", "zonealarm", "cb", "MsMpEng", "MsSense", "CSFalconService", "CSFalconContainer", "redcloak", "OmniAgent","CrAmTray","AmSvc","minionhost","PylumLoader","CrsSvc"];
            let adminTools = ["MobaXterm", "bash", "git-bash", "mmc", "Code", "notepad++", "notepad", "cmd", "drwatson", "DRWTSN32", "drwtsn32", "dumpcap", "ethereal", "filemon", "idag", "idaw", "k1205", "loader32", "netmon", "netstat", "netxray", "NmWebService", "nukenabber", "portmon", "powershell", "PRTG Traffic Gr", "PRTG Traffic Grapher", "prtgwatchdog", "putty", "regmon", "SystemEye", "taskman", "TASKMGR", "tcpview", "Totalcmd", "TrafMonitor", "windbg", "winobj", "wireshark", "WMonAvNScan", "WMonAvScan", "WMonSrv","regedit", "regedit32", "accesschk", "accesschk64", "AccessEnum", "ADExplorer", "ADInsight", "adrestore", "Autologon", "Autoruns", "Autoruns64", "autorunsc", "autorunsc64", "Bginfo", "Bginfo64", "Cacheset", "Clockres", "Clockres64", "Contig", "Contig64", "Coreinfo", "ctrl2cap", "Dbgview", "Desktops", "disk2vhd", "diskext", "diskext64", "Diskmon", "DiskView", "du", "du64", "efsdump", "FindLinks", "FindLinks64", "handle", "handle64", "hex2dec", "hex2dec64", "junction", "junction64", "ldmdump", "Listdlls", "Listdlls64", "livekd", "livekd64", "LoadOrd", "LoadOrd64", "LoadOrdC", "LoadOrdC64", "logonsessions", "logonsessions64", "movefile", "movefile64", "notmyfault", "notmyfault64", "notmyfaultc", "notmyfaultc64", "ntfsinfo", "ntfsinfo64", "pagedfrg", "pendmoves", "pendmoves64", "pipelist", "pipelist64", "portmon", "procdump", "procdump64", "procexp", "procexp64", "Procmon", "PsExec", "PsExec64", "psfile", "psfile64", "PsGetsid", "PsGetsid64", "PsInfo", "PsInfo64", "pskill", "pskill64", "pslist", "pslist64", "PsLoggedon", "PsLoggedon64", "psloglist", "pspasswd", "pspasswd64", "psping", "psping64", "PsService", "PsService64", "psshutdown", "pssuspend", "pssuspend64", "RAMMap", "RegDelNull", "RegDelNull64", "regjump", "ru", "ru64", "sdelete", "sdelete64", "ShareEnum", "ShellRunas", "sigcheck", "sigcheck64", "streams", "streams64", "strings", "strings64", "sync", "sync64", "Sysmon", "Sysmon64", "Tcpvcon", "Tcpview", "Testlimit", "Testlimit64", "vmmap", "Volumeid", "Volumeid64", "whois", "whois64", "Winobj", "ZoomIt", "KeePass", "1Password", "lastpass"];
            for(let j = 0; j < data.length; j++){
                let pinfo = data[j];
                let backgroundColor = "";
                let rowStyle = {};
                if (avProcesses.includes(pinfo["name"])) {
                    rowStyle = {
                        backgroundColor: "indianred",
                        color:"black"
                    };
                } else if (adminTools.includes(pinfo["name"])) {
                    rowStyle = {
                        backgroundColor: "rgb(106,255,255)",
                        color: "black"
                    };
                } else if (pinfo["name"] == "explorer" || pinfo["name"] == "winlogon") {
                    rowStyle = {
                        backgroundColor: "cornflowerblue",
                        color: "black",
                    };
                }
                let row = {
                    /*
                    {"plaintext": "ppid", "type": "number", "cellStyle": {}},
            {"plaintext": "pid", "type": "number", "cellStyle": {}},
            {"plaintext": "arch", "type": "string", "cellStyle": {}},
            {"plaintext": "name", "type": "string", "cellStyle": {}},
            {"plaintext": "session", "type": "number", "cellStyle": {}},
            {"plaintext": "signer", "type": "string", "cellStyle": {}},
            {"plaintext": "info", "type": "button", "cellStyle": {}, "width": 6},
                    */
                    // If process name is BAD, then highlight red.
                    "rowStyle": rowStyle,
                    "ppid": {"plaintext": pinfo["parent_process_id"], "cellStyle": {}, "copyIcon": true},
                    "pid": {"plaintext": pinfo["process_id"], "cellStyle": {}, "copyIcon": true},
                    "arch": {"plaintext": pinfo["architecture"], "cellStyle": {}},
                    "name": {"plaintext": pinfo["name"], "cellStyle": {}},
                    "user": {"plaintext": pinfo["user"], "cellStyle": {}},
                    "session": {"plaintext": pinfo["session_id"], "cellStyle": {}},
                    "signer": {"plaintext": pinfo["company_name"], "cellStyle": {}},
                    "actions": {"button": {
                        "name": "Actions",
                        "type": "menu",
                        "value": [
                            {
                                "name": "More Info",
                                "type": "dictionary",
                                "value": {
                                    "Process Path": pinfo["bin_path"],
                                    "File Description" : pinfo["description"],
                                    "Command Line": pinfo["command_line"],
                                    "Window Title": pinfo["window_title"]
                                },
                                "leftColumnTitle": "Attribute",
                                "rightColumnTitle": "Values",
                                "title": "Information for " + pinfo["name"]
                            },
                            {
                                "name": "Steal Token",
                                "type": "task",
                                "ui_feature": "steal_token",
                                "parameters": pinfo["process_id"]
                            },
                            {
                                "name": "Screenshot",
                                "type": "task",
                                "startIcon": "camera",
                                "ui_feature": "screenshot_inject",
                                "parameters": JSON.stringify({
                                    "pid": pinfo["process_id"],
                                    "count": 1,
                                    "interval": 0
                                })
                            },
                            {
                                "name": "Inject Keylogger",
                                "type": "task",
                                "startIcon": "inject",
                                "ui_feature": "keylog_inject",
                                "parameters": pinfo["process_id"]
                            },
                            {
                                "name": "Kill",
                                "type": "task",
                                "startIcon": "kill",
                                "ui_feature": "kill",
                                "parameters": pinfo["process_id"]
                            }
                        ]
                    }},
                };
                rows.push(row);
            }
        }
        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Process List"
        }]};
    }else{
        // this means we shouldn't have any output
        return {"plaintext": "Not response yet from agent..."}
    }
}