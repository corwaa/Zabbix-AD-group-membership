See blog on TrustedSec

# Can you do this with Zabbix?

Yes, but you need two approaches at once, because the article shows exactly where the usual approach falls short. If someone is added to Domain Admins and also gets it as their primaryGroupID, Get-ADGroup doesn’t show them as a member and Get-ADUser shows an empty memberOf, while Get-ADGroupMember and net group do show them. Nested groups make it worse: a user whose primary group is a nested group doesn’t show up in a recursive Get-ADGroupMember or LDAP query. And with a deny-read on primaryGroupID for Everyone, the membership becomes invisible on both the user and the group object. On top of that, a DCShadow attack bypasses the normal DC event logs entirely.

So: events for fast alerting, plus a state check that periodically compares the actual situation.

## 1. Event log on the DCs (fast, but not watertight)

First, in the Default Domain Controllers Policy under Advanced Audit Policy → Account Management, set Audit Security Group Management and Audit User Account Management to Success.

Then in Zabbix (eventlog only works as an active item, and it must run on every DC, because the event is only logged on the DC where the change happened):
```
eventlog[Security,,,,^(4728|4729|4732|4733|4756|4757)$,,skip]
```
Trigger: `find(/DC01/eventlog[...],,"regexp",".")=1`, with `nodata()` for recovery or manual close.

For primaryGroupID changes, event 4738 (user account changed) is relevant, but it’s very noisy. Filter on the field:
```
eventlog[Security,"Primary Group ID:\s+\d",,,^4738$,,skip]
```
On a Dutch-language Windows Server the field name is different; check a real 4738 event and adjust the regex.

## 2. State check via PowerShell (also catches DCShadow and the hiding trick)
[C:\Program Files\Zabbix Agent 2\scripts\privgroups.ps1](privgroups.ps1)

In the agent config (e.g. `zabbix_agent2.d\adpriv.conf`):
```
Timeout=30
UserParameter=ad.priv.members,powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\scripts\privgroups.ps1" -Mode members
UserParameter=ad.priv.pgid,powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\scripts\privgroups.ps1" -Mode pgid
```
Create the items as type Text with a 5–15 minute interval; one DC is enough (AD replicates). Triggers:

`change(/DC01/ad.priv.members)=1` → High: “Privileged group membership changed”. The history shows old vs. new.
`length(last(/DC01/ad.priv.pgid))>0` → High: “Account with non-standard primaryGroupID”.

The pgid check also catches the deny-read trick: the agent runs as LocalSystem (the DC computer account), so it falls under Everyone, gets `$null` back, and that falls outside the allowed list.

If you deliberately have accounts with a different primary group (for example for old POSIX/Mac integrations), add that RID to the allowed list, otherwise the trigger will keep firing. And if you want it extra tight, you can also add the output of `net group "Domain Admins" /domain`, since in the research that was the only method that correctly showed the hidden membership.
