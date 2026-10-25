FROM php:8.3-cli-alpine
WORKDIR /app
COPY index.php /app/index.php
CMD ["sh", "-c", "php -S 0.0.0.0:${PORT:-10000} /app/index.php"]
