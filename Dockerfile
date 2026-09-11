FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b
RUN apt-get update && apt-get install --no-install-recommends -y git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv==0.12.13
WORKDIR /opt/nvidia
RUN git init -q && git remote add origin https://github.com/NVIDIA/SkillSpector.git && git fetch -q --depth=1 origin 69dcdfb74487d361ba4c811d088cfdea2ff3a9dc && git checkout -q --detach FETCH_HEAD && test "$(git rev-parse HEAD)" = 69dcdfb74487d361ba4c811d088cfdea2ff3a9dc
RUN uv sync --frozen --no-dev --no-editable
ENV PATH="/opt/nvidia/.venv/bin:/usr/local/bin:/usr/bin:/bin" HOME=/tmp PYTHONDONTWRITEBYTECODE=1 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 LANGSMITH_TRACING=false LANGCHAIN_TRACING_V2=false REMOTE_SCANNER=1
COPY remote_scan.py /opt/remote_scan.py
WORKDIR /tmp
USER 65534:65534
ENTRYPOINT ["python", "-I", "-B", "/opt/remote_scan.py"]
