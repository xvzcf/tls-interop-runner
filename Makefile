all:
	cd implementations/boringssl && docker build -t bssl-endpoint . && cd ../../
	cd implementations/cloudflare-go && docker build -t cf-go-endpoint . && cd ../../
	cd implementations/rustls && docker build -t rustls-endpoint . && cd ../../