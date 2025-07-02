sudo docker buildx create --use

sudo docker buildx build --platform linux/arm64 -t go-file --lo
ad .

sudo docker save -o go-file.tar go-file
