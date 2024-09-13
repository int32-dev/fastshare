OUTDIR=../../bin

build-64: $(OUTDIR)
	cd cmd/fastshare && CGO_ENABLED=0 go build -o $(OUTDIR)/fastshare-linux-amd64

build-linux-arm64: $(OUTDIR)
	cd cmd/fastshare && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(OUTDIR)/fastshare-linux-arm64

build-windows-64: $(OUTDIR)
	cd cmd/fastshare && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(OUTDIR)/fastshare-win-amd64.exe

build-windows-arm64: $(OUTDIR)
	cd cmd/fastshare && CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -o $(OUTDIR)/fastshare-win-arm64.exe

upload: build-64
	scp bin/fastshare-linux-amd64 servy2:~/fastshare

$(OUTDIR):
	mkdir $(OUTDIR)

all: build-64 build-linux-arm64 build-windows-64 build-windows-arm64 server-64 server-linux-arm64 server-windows-64 server-windows-arm64

server-64: frontend $(OUTDIR)
	cd cmd/fastshare-server && CGO_ENABLED=0 go build -o $(OUTDIR)/fastshare-server-linux-amd64

server-linux-arm64: $(OUTDIR)
	cd cmd/fastshare-server && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(OUTDIR)/fastshare-server-linux-arm64

server-windows-64: $(OUTDIR)
	cd cmd/fastshare-server && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(OUTDIR)/fastshare-server-win-amd64.exe

server-windows-arm64: $(OUTDIR)
	cd cmd/fastshare-server && CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -o $(OUTDIR)/fastshare-server-win-arm64.exe

frontend:
	cd web && ng build
	mkdir -p cmd/fastshare-server/web
	cp -r web/dist cmd/fastshare-server/web