# Ghidra 11.0.3 headless analysis pipeline
# Java 17 is required by Ghidra 11.x
FROM eclipse-temurin:17-jdk-jammy

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ghidra-pipeline

# Copy Ghidra installation
COPY ghidra_11.0.3_PUBLIC/ /opt/ghidra/

# Install pyhidra
RUN pip3 install --no-cache-dir pyhidra

# Install extensions into Ghidra's system extensions directory.
# Each .zip is expected to contain a top-level folder with extension.properties.
# Ghidra discovers extensions by scanning <install>/Ghidra/Extensions/ for
# directories containing extension.properties.
COPY extensions/ /tmp/extensions/
RUN for zip in /tmp/extensions/*.zip; do \
        [ -f "$zip" ] || continue; \
        echo "Installing extension: $(basename $zip)"; \
        unzip -q "$zip" -d /opt/ghidra/Ghidra/Extensions/; \
    done \
    && rm -rf /tmp/extensions/ \
    # Verify extensions were installed
    && echo "Installed extensions:" \
    && find /opt/ghidra/Ghidra/Extensions/ -name "extension.properties" -exec echo "  {}" \; \
    # Fix protobuf version conflict: BinExport needs 3.25.1, Ghidra ships 3.21.8
    && if [ -f /opt/ghidra/Ghidra/Extensions/BinExport/lib/protobuf-java-3.25.1.jar ]; then \
        echo "Fixing protobuf version conflict..."; \
        cp /opt/ghidra/Ghidra/Extensions/BinExport/lib/protobuf-java-3.25.1.jar \
           /opt/ghidra/Ghidra/Debug/Framework-AsyncComm/lib/protobuf-java-3.21.8.jar; \
        echo "  Replaced Ghidra protobuf 3.21.8 with BinExport protobuf 3.25.1"; \
    fi

# Copy analysis scripts and entry point
COPY Scripts/ /opt/ghidra-pipeline/Scripts/
COPY headless_analyze.py /opt/ghidra-pipeline/

# Runtime environment
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PYTHONUTF8=1
# Override Java's user.name so Ghidra projects can be opened by any user.
# Pass -e GHIDRA_USER=YourWindowsUsername at docker run to match your host user,
# or leave as default — the entrypoint patches .gpr files after analysis.
ENV GHIDRA_USER=""

# /input  — bind-mount your binaries here at runtime
# /output — bind-mount your output directory here at runtime
VOLUME ["/input", "/output"]

# Fixed arguments in ENTRYPOINT, only project name value is passed via CMD
# Usage: docker run -v /path/to/binaries:/input -v /path/to/output:/output <image> <project-name>
ENTRYPOINT ["python3", "/opt/ghidra-pipeline/headless_analyze.py", \
            "/input", \
            "--scripts-dir", "/opt/ghidra-pipeline/Scripts", \
            "--project-dir", "/output", \
            "--project-name"]
CMD ["DefaultProject"]
