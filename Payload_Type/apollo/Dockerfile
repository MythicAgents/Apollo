FROM itsafeaturemythic/mythic_base_image:0.0.2

RUN python3 -m pip install mythic-container==0.2.0rc6
RUN python3 -m pip install donut-shellcode

WORKDIR /Mythic/

CMD ["python3", "main.py"]