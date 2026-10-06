set -e
docker buildx build --progress=plain --target artifact --output type=local,dest='./out' .
echo 'Run out/minimal'