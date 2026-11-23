set -e
docker buildx build --progress=plain --target artifact --output type=local,dest='./out' .
echo 'Run: sudo out/auditor /sys/fs/cgroup/denied'
