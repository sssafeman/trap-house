.PHONY: up down logs test clean prod-up prod-down prod-logs

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

test:
	python3 -m unittest discover -s tests -v
	./verify.sh

clean:
	docker compose down -v

# Production targets (Hetzner)
prod-up:
	COMPOSE_ENV_FILES=.env.hetzner docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

prod-down:
	COMPOSE_ENV_FILES=.env.hetzner docker compose -f docker-compose.yml -f docker-compose.prod.yml down

prod-logs:
	COMPOSE_ENV_FILES=.env.hetzner docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f