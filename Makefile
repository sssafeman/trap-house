.PHONY: up down logs test clean prod-up prod-down prod-logs

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

# Production targets (Hetzner)
prod-up:
	docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env.hetzner up -d

prod-down:
	docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env.hetzner down

prod-logs:
	docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env.hetzner logs -f