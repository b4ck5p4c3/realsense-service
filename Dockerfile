FROM ghcr.io/astral-sh/uv:trixie
WORKDIR /app
RUN uv venv /app/venv
ENV VIRTUAL_ENV=/app/venv
ENV PATH="/app/venv/bin:$PATH"
COPY requirements.txt requirements.txt
RUN uv pip install --python 3.12 -r requirements.txt
RUN uv pip install --python 3.12 https://github.com/radioegor146/RealSenseID/releases/download/v3/rsid_py_secure-3.6.1-cp312-cp312-manylinux_2_27_aarch64.manylinux_2_28_aarch64.whl
COPY . .
CMD ["uv", "run", "main.py"]