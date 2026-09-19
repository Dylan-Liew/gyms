## NFS — 111, 2049

```bash
# List registered RPC services.
rpcinfo -p "$IP" | tee rpc.txt
# List exported NFS shares.
showmount -e "$IP" | tee nfs.txt
# Create a local mount point.
sudo mkdir -p /mnt/nfs
# Mount the public NFS export.
sudo mount -t nfs "$IP:/public-nfs" /mnt/nfs -o nolock
# List files in the mounted export.
find /mnt/nfs -maxdepth 3 -ls | tee nfs-files.txt
# Unmount the export.
sudo umount /mnt/nfs
```

```text
Export list for 192.168.50.20:
/public-nfs *
```
