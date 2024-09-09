OUTDIR=../../bin

build-64: $(OUTDIR)
	cd cmd/fastshare && CGO_ENABLED=0 go build -o $(OUTDIR)/fastshare-linux-amd64

build-linux-arm64: $(OUTDIR)
	cd cmd/fastshare && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(OUTDIR)/fastshare-linux-arm64

build-windows-64: $(OUTDIR)
	cd cmd/fastshare && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(OUTDIR)/fastshare-win-amd64.exe

build-windows-arm64: $(OUTDIR)
	cd cmd/fastshare && CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -o $(OUTDIR)/fastshare-win-arm64.exe

upload: build
	scp cmd/fastshare/fastshare servy2:~

$(OUTDIR):
	mkdir $(OUTDIR)

all: build-64 build-linux-arm64 build-windows-64 build-windows-arm64