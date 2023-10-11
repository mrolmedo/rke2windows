### RKE2 Windows Agent commands
Use PowerShell (as Administrator).

### Binaries
```C:\var\lib\rancher\rke2\bin> ls -Name
calico-ipam.exe
calico-node.exe
calico.exe
containerd-shim-runhcs-v1.exe
containerd.exe
crictl.exe
ctr.exe
hns.psm1
host-local.exe
kube-proxy.exe
kubectl.exe
kubelet.exe
win-overlay.exe
```
### Kubeconfig
```
kubeconfig / kubectl
set KUBECONFIG="C:\var\lib\rancher\rke2\agent\kubelet.kubeconfig"
"C:\var\lib\rancher\rke2\bin\kubectl.exe" get node
```
### ctr
List containers using ctr
```
ctr --address "\\.\\pipe\\containerd-containerd" --namespace k8s.io container ls
List images

ctr --address "\\.\\pipe\\containerd-containerd" --namespace k8s.io image ls
crictl
"C:\var\lib\rancher\rke2\bin\crictl.exe" -r "npipe:////./pipe/containerd-containerd" ps
```

### Prechecks

- [:white_check_mark:] WindowsOptionalFeature  Installed and Enable
```
Get-WindowsOptionalFeature -Online -FeatureName constainers
Get-WindowsFeature -Name Containers
```
- [:white_check_mark:] Kubelet, kube-proxy, calico running, containerd, containerd-shim-runhcs-v1
```
 Get-Process -Name calico-node,kubelet,containerd,kube-proxy,containerd-shim-runhcs-v1
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    256      16    27692      40384   1,713.33   2748   0 calico-node
    313      22    43180      52568   2,244.58   3440   0 containerd
    184      11    17416      17112      15.42    656   0 containerd-shim-runhcs-v1
    346      25    49032      67980   7,920.91   2116   0 kubelet
    197      17    27320      37516     181.41    440   0 kube-proxy
```
- [:white_check_mark:] HNS running
```
Get-Service hns
```
- [:white_check_mark:] Rancher wins
```
Get-Service| Where-Object { $_.Name -like '*rancher-wins*'}

Status   Name               DisplayName
------   ----               -----------
Running  rancher-wins       Rancher Wins
```
### Kubelet logs
```
C:\var\lib\rancher\rke2\agent\logs>kubelet.log
```
### Event logs
```
Get-EventLog -LogName Application -Source 'rke2'  -Newest 500 | format-table  -Property TimeGenerated, ReplacementStrings -Wrap
Get-EventLog -LogName Application -Source 'rancher-wins'  -Newest 500 | format-table  -Property TimeGenerated, ReplacementStrings -Wrap
```

### Collect logs
- https://github.com/rancherlabs/support-tools/tree/master/collection/rancher/v2.x/windows-log-collector


### Rancher system-agent-service
```
Status :
C:\Windows\system32> Get-Service| Where-Object { $_.Name -like '*rancher-wins*'}

C:\Windows\system32> Get-Service| Where-Object { $_.Name -like '*rke2*'}




PS C:\Windows\system32> Get-Service -DisplayName 'Rancher wins'

Status   Name               DisplayName
------   ----               -----------
Running  rancher-wins       Rancher Wins


PS C:\Windows\system32> Get-Service -DisplayName 'rke2'

Status   Name               DisplayName
------   ----               -----------
Running  rke2               rke2
```
### Endpoints
   - *List endpoints*
```
PS C:\logpath>hnsdiag list all
Output example
Endpoint         : c9385412-bdef-49f5-88b0-c9d484ef6716
    Name             : 4a625a2b10a33b0dea96fe8743fb8e13504481ee9f481d179f8e75b8c98611d2_Calico
    IP Address       : 10.42.213.221 ### pod IP
```

  - *Inspect endpoint*
```
PS C:\logpath> get-hnsendpoint | ? ID -Like "c9385412-bdef-49f5-88b0-c9d484ef6716"
ID                 : c9385412-bdef-49f5-88b0-c9d484ef6716
Name               : 4a625a2b10a33b0dea96fe8743fb8e13504481ee9f481d179f8e75b8c98611d2_Calico
Version            : 55834574851
AdditionalParams   :
Resources          : @{AdditionalParams=; AllocationOrder=14; Allocators=System.Object[]; CompartmentOperationTime=0; Flags=0; Health=; ID=36C2BD3E-FB53-4E32-8897-5ECBD3679415; PortOperationTime=0; State=1; SwitchOperationTime=0; VfpOperationTime=0; parentId=40963662-0489-4EBA-9F44-EB6AD695F35E}
State              : 3
VirtualNetwork     : 06560ccd-89f3-4c69-a1a1-e9e368201482
VirtualNetworkName : Calico
Policies           : {@{ExceptionList=System.Object[]; Type=OutBoundNAT}, @{DestinationPrefix=10.43.0.0/16; NeedEncap=True; Type=ROUTE}, @{PA=10.156.233.218; Type=PA}, @{Action=Allow; Direction=In; Id=allow-host-to-endpoint; InternalPort=0; LocalAddresses=; LocalPort=0; Priority=900; Protocol=256; RemoteAddresses=10.156.233.218/32; RemotePort=0; RuleType=Switch; Scope=0; ServiceName=; Type=ACL}...}
MacAddress         : 0E-2A-0a-2a-d5-dd
IPAddress          : 10.42.213.221
PrefixLength       : 26
GatewayAddress     : 10.42.213.193
IPSubnetId         : 2b41a5a7-6228-4df4-a6a4-51624b9d8e91
DNSServerList      : 10.43.0.10
DNSSuffix          : rke2-tcp-reset-test.svc.cluster.local,svc.cluster.local,cluster.local
Namespace          : @{ID=4ea04396-a6e5-478f-915e-909b8c80b2ef}
EncapOverhead      : 50
SharedContainers   : {4a625a2b10a33b0dea96fe8743fb8e13504481ee9f481d179f8e75b8c98611d2, 437cdcccbad47d99dca87acb3b0256d2aa988a19b5fba17241c14ba6e9d86da0}

```
- List ACL_ENDPOINT_LAYER for a port ### Network policies in Windows are implemented by the VFP (Virtual Filtering Platform) system. Specifically, by the "ACL_ENDPOINT_LAYER".
```
vfpctrl /port c9385412-bdef-49f5-88b0-c9d484ef6716 /layer ACL_ENDPOINT_LAYER /list-rule
 ITEM LIST
===========

  GROUP : ACL_ENDPOINT_GROUP_IPV4_IN
      Friendly name : ACL_ENDPOINT_GROUP_IPV4_IN
      Priority : 1
      Direction : IN
      Type : IPv4
        Conditions:
            <none>
      Match type : Priority-based match

    RULE : A2CFF68C-B5F4-4988-841F-0F6F77AF3D09
        Friendly name : allow-host-to-endpoint
        Priority : 900
        Flags : 8195 terminating stateful 
        Type : allow
        Conditions:
            Source IP : 10.156.233.218
        Flow TTL: 240
        FlagsEx : 0 

    RULE : 0EE8DCA1-9AA8-417C-88E0-422CE9E52CBF
        Friendly name : profile-kns.rke2-tcp-reset-test--atbkwj8tPVFG3P1-0
        Priority : 1000
        Flags : 8195 terminating stateful 
        Type : allow
        Conditions:
            <none>
        Flow TTL: 240
        FlagsEx : 0
  (redacted)
```


| Linux | Windows| 
| --- | --- |  
| wget |Invoke-WebRequest -Uri https://xxxx -OutFile "filename" || Invoke-WebRequest -Uri http://aka.ms/gettssv2  -OutFile gettssv2.zip
| gunzip |  Expand-Archive -Path .\gettssv2.zip -DestinationPath ./gettssv
