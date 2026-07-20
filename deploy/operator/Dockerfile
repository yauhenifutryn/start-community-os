FROM python:3.13-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates chromium poppler-utils \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 operator \
    && mkdir -p /srv/start-community/operator-data \
    && chown -R operator:operator /srv/start-community
WORKDIR /app
COPY --chown=operator:operator community_os /app/community_os
COPY --chown=operator:operator mappings /app/mappings
COPY --chown=operator:operator assets /app/assets
USER operator

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
EXPOSE 8766
VOLUME ["/srv/start-community/operator-data"]

CMD ["python", "-m", "community_os", "release-operator", "--host", "0.0.0.0", "--port", "8766", "--root", "/srv/start-community/operator-data", "--operator-code", "privacy_lead"]
