#FROM itsafeaturemythic/mythic_python_dotnet:latest
FROM mcr.microsoft.com/dotnet/sdk:8.0
RUN apt-get update && apt-get install python3 python3-pip python3.11-venv -y


WORKDIR /Mythic/
RUN python3 -m venv /venv
RUN /venv/bin/python -m pip install mythic-container==0.5.9
RUN /venv/bin/python -m pip install donut-shellcode
RUN /venv/bin/python -m pip install mslex

COPY [".", "."]

# fetch all dependencies
RUN cd apollo/agent_code && dotnet restore

CMD ["/venv/bin/python", "main.py"]
