#FROM itsafeaturemythic/mythic_python_dotnet:latest
FROM mcr.microsoft.com/dotnet/sdk:8.0
RUN apt-get update && apt-get install python3 python3-pip python3.11-venv -y

RUN curl -L -o donut_shellcode-2.0.0.tar.gz https://github.com/MEhrn00/donut/releases/download/v2.0.0/donut_shellcode-2.0.0.tar.gz && \
    tar -xf donut_shellcode-2.0.0.tar.gz && \
    cd donut_shellcode-2.0.0 && \
    make && \
    cp donut / && \
    rm -rf donut_shellcode-2.0.0 && \
    rm -rf donut_shellcode-2.0.0.tar.gz

WORKDIR /Mythic/
RUN python3 -m venv /venv
RUN /venv/bin/python -m pip install mythic-container==0.5.9
RUN /venv/bin/python -m pip install git+https://github.com/MEhrn00/donut.git@v2.0.0
RUN /venv/bin/python -m pip install mslex

COPY [".", "."]

# fetch all dependencies
RUN cd apollo/agent_code && dotnet restore && rm donut ; cp /donut donut

CMD ["bash", "-c", "cp /donut apollo/agent_code/donut && /venv/bin/python main.py"]
