# EIPP Banned Password Lists

Tools for manipulating Banned Password Lists (BPL) of Entra ID Password
Protection.

The `eipp-global-bpl.txt` containing the entries of the global banned password
list was dumped on 2024-04-11.

More info at https://www.synacktiv.com/en/publications/entra-id-banned-password-lists-password-spraying-optimizations-and-defenses.

## EIPPDecrypt

This utility can be used to extract the configuration and password policies of
an on-premises Entra ID Password Protection deployment. It relies on the DC
Agent DLLs and must be executed on the domain controller.

```
PS> cp 'C:\Program Files\Azure AD Password Protection DC Agent\Rules\1.0.0.0\ServiceCommon.dll' .
PS> cp 'C:\Program Files\Azure AD Password Protection DC Agent\Rules\1.0.0.0\ServiceCommonHelper.dll' .
PS> cp 'C:\Program Files\Azure AD Password Protection DC Agent\Rules\1.0.0.0\vcruntime140.dll' .
PS> .\EIPPDecrypt.exe \\localhost\SYSVOL\CORP.LOCAL\AzureADPasswordProtection\Configuration\*.cfge
PS> .\EIPPDecrypt.exe \\localhost\SYSVOL\CORP.LOCAL\AzureADPasswordProtection\PasswordPolicies\*.ppe
```

Files with the `.ppe` extension contain the password policy including the
global and custom BPL with their timestamp.

```
$ jq -r .GlobalBPLTimestampUTC policy.json
2020-10-30T00:00:00Z

$ jq -r .GlobalBPL policy.json | tr '\t' '\n' | wc -l
3270

$ jq -r .GlobalBPL policy.json | tr '\t' '\n'
administracion123
administrador123
administrateur123
administrator123
administrator2022
administrator2023
password1
password12
password123
[...]
```

## EIPP

This utility can be used to generate an optimized custom BPL from a list of
compromised passwords. It was designed for large datasets (10k passwords) and
may produce poor results on smaller lists.

```
PS> .\EIPP.exe
usage:
  EIPP.exe normalize passwords.txt
  EIPP.exe generate [-t threads] [-m minOccurences] [-n entries] passwords.txt global.txt output.txt
  EIPP.exe stats [-t threads] passwords.txt global.txt [tenant.txt]
```

The `normalize` command is used to normalize passwords according to the EIPP
algorithm (lowercase and substitutions). It takes the list of passwords to
normalize and output results to stdout without sorting.

```
PS> cat passwords.txt
Company2024
PS> .\EIPP.exe normalize passwords.txt
companyzoz4
```

The `generate` command is used to generate an optimized custom BPL. It takes
the list of passwords to ban (from a password audit for instance), the global
BPL and the name of the output file (`custom.txt` here). Speed can be adjusted
with the number of threads (`-t`, defaults to `4`) and the minimum number of
occurences for an entry to be considered (`-m`, defaults to `5`). The `-n`
option may also be used to change the default number of entries to generate,
which could prove useful if the entity already has entries in its custom BPL.

```
PS> .\EIPP.exe generate passwords.txt global.txt custom.txt
PS> .\EIPP.exe generate -t 8 -m 10 -n 500 passwords.txt global.txt custom.txt
Progress: 1234/23456 (5%)
```

The `stats` command is used to compute the ban rate of a custom BPL and assess
its efficiency. It takes the list of passwords to ban, the global and custom
BPLs. It may also be used without the custom BPL to assess the efficiency of
the global BPL alone (which is generally low).

```
PS> .\EIPP.exe stats passwords.txt global.txt [tenant.txt]
PS> .\EIPP.exe stats -t 8 passwords.txt global.txt tenant.txt
Results: 37% banned
```

