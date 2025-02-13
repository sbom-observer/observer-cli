# check if argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <path-to-directory>"
    exit 1
fi

trivy fs --skip-db-update --skip-java-db-update --format cyclonedx --output /tmp/trivy.cdx.json $1
go run . --debug repo --merge -o /tmp/scalibr.cdx.json $1
go run main.go diff /tmp/trivy.cdx.json /tmp/scalibr.cdx.json