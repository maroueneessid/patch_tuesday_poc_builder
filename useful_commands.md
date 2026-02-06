# Get Updated files


### Find files updated on a specific date. 
`Get-ChildItem C:\Windows\WinSxS -Directory | Where-Object {$_.LastWriteTime.Date -eq (Get-Date "2026-01-14").Date} | Select-Object FullName, LastWriteTime`


### Get unique dll names from interesting folder list

```
Get-ChildItem `
  'C:\Windows\WinSxS\amd64_microsoft-windows-rasbase-rascustom_31bf3856ad364e35_10.0.26100.7623_none_94cb8c626ccc1a0b',
  'C:\Windows\WinSxS\amd64_microsoft-windows-rasmanservice_31bf3856ad364e35_10.0.26100.7623_none_3a6b9d4a50bde759',
  'C:\Windows\WinSxS\amd64_microsoft-windows-rasserver_31bf3856ad364e35_10.0.26100.7623_none_4757406017e2450f', `
  -Recurse -File -Filter *.dll |
Select-Object -ExpandProperty Name -Unique
```

### Find RPCs
```
Set-ExecutionPolicy Bypass -Scope Process
Import-Module NtObjectManager
Set-GlobalSymbolResolver -DbgHelpPath 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll'
$testfile = "C:\test.txt"
$rpcinterfaces = 'C:\Windows\System32\rasmans.dll' | Get-RpcServer
$client = $rpcinterfaces[0] | Get-RpcClient

$client.Connect('\RPC Control\RasmanLrpc') 

echo $client

$client | Get-Member -MemberType Method


```

### Resources
- https://winbindex.m417z.com/
- https://www.incendium.rocks/posts/Automating-MS-RPC-Vulnerability-Research/#chapter-3--ntobjectmanager
