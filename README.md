# K8s Home Lab
This repository should contain all required steps, manifests and resources to set up a K8s in a home lab environment. Its status should be viewed as "work in progress" since I plan to improve various things in the future.

## Technologies
Currently there's only a rough plan about which technologies should be used for this setup. The list down here will definitely change as soon as the project progresses.

| What | Technology |
|---|---|
| DNS Provider | DigitalOcean |
|  | DigitalOcean |
| Hypervisor | Qemu-KVM (VT-x is enabled) |
| Hypervisor OS (Intel NUC) | CentOS 8 |
| Control Plane | Rancher (HA mode) |
| Control Plane K8s Distributon | Rancher (RKE) |
| Control Plane Node OS | CentOS 7 |
| Control Plane Node Container Engine | Docker CE (containerd) |
| Control Plane Node CRI Runtime | RunC |
| Control Plane K8s CNI | Calico |
| Control Plane HA Setup | keepalived as Daemonset |
| Control Plane Certificate Handling | Cert-Manager with Let's Encrypt (DNS Challenge) |
| Control Plane Ingress Controller | Nginx |
| Control Plane Backup | Ranchers S3 Backup Capability (DigitalOcean Spaces) |
| Custom Cluster K8s Distributon | K3s |
| Custom Cluster Node OS | Alpine |
| Custom Cluster Node Container Engine | Docker CE (containerd) |
| Custom Cluster Node CRI Runtime | RunC |
| Custom Cluster K8s CNI | Cilium |
| Custom Cluster HA Setup | keepalived as Daemonset |
| Custom Cluster Certificate Handling | Cert-Manager with Let's Encrypt (DNS Challenge) |
| Custom Cluster Infra App Deployment | Helm & mostly ArgoCD |
| Custom Cluster Ingress Controller | Nginx |
| Custom Cluster Logging | Grafana Loki (via Rancher Logging) |
| Custom Cluster Backup | Velero |

## Hardware
One goal of this setup is that it should be runnable on a single host which that acts as Qemu-KVM hypervisor. The only exceptions are the external NFS storage from a Synology NAS and a DNS service from DigitalOcean.

In my case I use an Intel NUC (`NUC10i7FNH2`) with a 12 core CPU (`Intel(R) Core(TM) i7-10710U CPU @ 1.10GHz`) and 64 GB memory (`2 x 32 GB DDR4-2666`).

## Topology
![K8s Home Lab Topology](images/K8s-Home-Lab-Drawing.png)

## Getting Started

### Hypervisor
TODO