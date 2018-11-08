## Format of /loot

On each homebase instance there is a `/loot` directory that will store engagement specific loot. This directory needs to be organized in a methodological way to ease reporting, tracking and gauge overall mission success. The directory has permissions of 1777.

A wiki entry must be made for every host that has loot in `/loot` as well.

The structure of the loot directory needs to be the following

```
/loot
- HOSTNAME
-- <loot1 directory>
---- README.MD describing loot
---- <actual loot>
-- <loot2 directory>
---- README.MD describing loot
---- <actual loot>
- HOSTNAME
-- <loot1 directory>
---- README.MD describing loot
---- <actual loot>
```

An example of this would be the following

```
/loot
- REDTEAM-MOBL1
-- RTJ-Certificate
---- README.MD describing loot
---- certificate.crt
-- RTJ-UEFI
---- README.MD describing loot
---- UEFI.thg
- VICTIM13
-- ITS-Documents
---- README.MD describing loot
---- Document1.txt
---- Document2.pdf
---- Document3.md
```

each README.md MUST be filled out to describe the loot. An example of this would be

```
## Title of Loot

This loot was obtained from <hostname> via <method> and is relevant to the engagement because <why this loot is important to us>.
```

