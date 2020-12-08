# K8s Home Lab
This repository should contain all required steps, manifests and resources to set up a K8s in a home lab environment. Its status should be viewed as "work in progress" since I plan to improve various things in the future.

## Technologies
Currently there's only a rough plan about which technologies should be used for this setup. The list down here will definitely change as soon as the project progresses.

| What | Technology |
|---|---|
| DNS Provider | DigitalOcean |
| OS (Intel NUC) | Red Hat 8 |
| Distributon | Rancher (RKE2) |
| CRI | containerd |
| CNI | Cilium |
| CSI | NFS / DigitalOcean |
| Certificate Handling | Cert-Manager with Let's Encrypt (DNS Challenge) |
| Ingress Controller | Nginx |
| ETCD Backup | RKE2's S3 Backup Capability (to DigitalOcean Spaces) |
| Data Backup | Kanister |
| App Deployment | Helm & mostly ArgoCD |
| Logging | Grafana Loki (via Rancher Logging) |
| Registry | Harbor |

## Hardware
One goal of this setup is that it should be runnable on a single host. The only exceptions are the external NFS storage from a Synology NAS and the DNS/S3/storage service from DigitalOcean.

In my case I use an Intel NUC (`NUC10i7FNH2`) with a 12 core CPU (`Intel(R) Core(TM) i7-10710U CPU @ 1.10GHz`) and 64 GB memory (`2 x 32 GB DDR4-2666`).

## Topology
![K8s Home Lab Topology](images/K8s-Home-Lab-Drawing.png)

## Prerequisites

## Getting Started
```bash

```