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
ctr
List containers using ctr

ctr --address "\\.\\pipe\\containerd-containerd" --namespace k8s.io container ls
List images

ctr --address "\\.\\pipe\\containerd-containerd" --namespace k8s.io image ls
crictl
"C:\var\lib\rancher\rke2\bin\crictl.exe" -r "npipe:////./pipe/containerd-containerd" ps
logging
rke2 service logs:

Get-EventLog Application -Source rke2 -Newest 50 | Select-Object -Property ReplacementStrings

### Collect logs
- https://github.com/rancherlabs/support-tools/tree/master/collection/rancher/v2.x/windows-log-collector
