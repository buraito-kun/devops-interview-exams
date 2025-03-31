# SECURITY ISSUE: Using latest tag instead of specific version
FROM python:3.9@sha256:bc2e05bca883473050fc3b7c134c28ab822be73126ba1ce29517d9e8b7f3703b AS build

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# -------- MULTI STAGE -----------

# use slim version
FROM python:3.9-slim-bullseye@sha256:5ece09c3d27b302ce8a3d87c6c7e33ee144329b757e68ae7b6ed2fc807dc44d5

# set working directory
WORKDIR /app

# SECURITY ISSUE: Running as root
# add non-root user
RUN groupadd -r nonroot && useradd -r -g nonroot nonroot

# use non-root user
USER nonroot

# copy dependency from build
COPY --from=build /root/.local /home/nonroot/.local

# copy application code and change owner
COPY --chown=nonroot:nonroot . .

# SECURITY ISSUE: Using environment variables for sensitive information
# ENV DB_PASSWORD="supersecretpassword"
# pass DB_PASSWORD through docker cli command
ENV DEBUG=True

# SECURITY ISSUE: Exposing unnecessary ports
# expose application used port
EXPOSE 5000

# SECURITY ISSUE: Running with high privileges
CMD ["python", "app.py"]
