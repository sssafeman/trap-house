.PHONY: up down logs test clean

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

test:
	./verify.sh

clean:
	docker compose down -v