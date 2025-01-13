Prometheus_image = prom/prometheus
all:
	go mod tidy
	go build -o data-visual ./main.go
	@mkdir -p ./.output/data
	@touch ./.output/data/offcpu_stack.txt

start_service:
	./runimages.sh

clean_data:
	rm -rf ./dao/data.db ./.output/data
