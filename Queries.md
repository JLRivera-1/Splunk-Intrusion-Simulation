## Phase 1 — Brute Force Detection (T1110)
```spl
index=sysmon_lab EventCode=4625
| bucket _time span=1h
| stats count by _time, Account_Name
| where count > 5 AND Account_Name!="josel"
```

## Phase 2 — Privilege Escalation Detection (T1053.005)
```spl
index="sysmon_lab" EventCode=1 User="BeboPC\\TargetUser" ParentImage!="*runas*"
| table _time, User, Image, CommandLine, IntegrityLevel, ParentImage
| sort _time
```

## Phase 3 — Persistence Detection (T1547.001)
```spl
index="sysmon_lab" EventCode=11 User="BeboPC\\TargetUser" (Image="*cmd.exe*" OR Image="*powershell*") TargetFilename!="*Temp*" earliest="03/11/2026:00:00:00"
| table _time, User, TargetFilename, Image, ProcessId
| sort _time
```