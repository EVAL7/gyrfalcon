# syntax=docker/dockerfile:1
#
# Образ gyrfalcon: индекс собирается и отвечает внутри контейнера.
#
# Зачем он вообще. Stdio требует, чтобы клиент запускал бинарь сам, — в
# контейнере это делается через `docker run -i`, и так оно и работает. HTTP
# нужен там, где команду выполнить нечем; ради этого случая у сервера и есть
# `--bind`, потому что петля внутри контейнера снаружи недостижима.

# ── Сборка ───────────────────────────────────────────────────────────────
#
# Образ полный, а не `-slim`: rusqlite собирает SQLite из исходников, а
# грамматики BSL и SDBL — своим build.rs, и обоим нужен cc, которого в slim
# нет. Тег `1-bookworm` — любая стабильная 1.x; нижняя граница проекта 1.85
# задана в rust-version и проверяется самим cargo.
FROM rust:1-bookworm AS build

WORKDIR /build
COPY . .

# Кэш реестра и каталога сборки живут вне слоя, поэтому готовый бинарь
# копируется наружу тем же RUN: после него содержимое target/ недоступно.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p gyrfalcon-mcp \
 && cp target/release/gyrfalcon /gyrfalcon

# ── Запуск ───────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="gyrfalcon" \
      org.opencontainers.image.description="Справочно-навигационный сервер по 1С:Предприятие (BSL) для LLM-агентов" \
      org.opencontainers.image.source="https://github.com/aleksandrgradoboev-svg/gyrfalcon" \
      org.opencontainers.image.licenses="MIT"

# git нужен серверу на месте исполнения — без него не работает всё,
# что смотрит в рабочую копию репозитория.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

# Пользователь без прав: сервер только читает — индекс открывается
# read-only, в конфигурацию он не пишет, в сеть не ходит. Root ему не нужен
# ни для чего, а собранный индекс, наоборот, должен быть ему читаем: при
# монтировании чужого каталога помогает `--user "$(id -u):$(id -g)"`.
RUN useradd --system --uid 10001 --user-group --create-home gyrfalcon

COPY --from=build /gyrfalcon /usr/local/bin/gyrfalcon

# Словарь семантики едет внутрь образа: он нужен каждой сборке индекса, и
# без него `find` теряет семантический сигнал. Путь фиксирован, чтобы
# команда сборки не зависела от того, куда его положил человек:
#
#   build /src --out /data/config.db --dict /usr/share/gyrfalcon/dictionary.db
#
# 40 МБ к образу — цена того, что сборка работает из коробки, а не после
# отдельного монтирования, о котором надо помнить.
COPY data/dictionary-all-configs.db /usr/share/gyrfalcon/dictionary.db

USER 10001:10001
WORKDIR /data
EXPOSE 8788

# Без аргументов — справка, а не сервер: пути к индексу образ не знает, и
# угаданный им путь был бы ответом про чужой индекс.
ENTRYPOINT ["gyrfalcon"]
CMD ["--help"]
