build: 
	cd cmd/fastshare && CGO_ENABLED=0 go build

build-windows:
	cd cmd/fastshare && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build

upload: build
	scp cmd/fastshare/fastshare servy2:~