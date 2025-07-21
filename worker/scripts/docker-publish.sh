# build docker image
docker buildx build --load --platform linux/amd64 -t near-tee-rng:latest -f Dockerfile .

# publish docker image
export OWNER=robortyan
docker tag near-tee-rng:latest ${OWNER}/near-tee-rng:latest
docker push ${OWNER}/near-tee-rng:latest
