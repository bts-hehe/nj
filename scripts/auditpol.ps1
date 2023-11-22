Write-Output "`n---Setting Audit Policy"
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"DS Access" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable

    auditpol /set /category:* /success:enable
    auditpol /set /category:* /failure:enable
    auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
    auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
    auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
    auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
    auditpol /set /subcategory:"IPsec Main Mode" /success:enable /failure:enable
    auditpol /set /subcategory:"IPsec Quick Mode" /success:enable /failure:enable
    auditpol /set /subcategory:"IPsec Extended Mode" /success:enable /failure:enable
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
    auditpol /set /subcategory:"User / Device Claims" /success:enable /failure:enable
    auditpol /set /subcategory:"Group Membership" /success:enable /failure:enable
    auditpol /set /subcategory:"File System" /success:enable /failure:enable
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable
    auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
    auditpol /set /subcategory:"SAM" /success:enable /failure:enable
    auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
    auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
    auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable
    auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
    auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
    auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
    auditpol /set /subcategory:"Central Policy Staging" /success:enable /failure:enable
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
    auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
    auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
    auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
    auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
