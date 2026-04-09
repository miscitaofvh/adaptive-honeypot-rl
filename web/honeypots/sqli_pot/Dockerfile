FROM python:3.12-slim
WORKDIR /app
COPY base.py      /app/shared/honeypot_base.py
COPY fake_data.py /app/shared/fake_data.py
COPY sqli_pot/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY sqli_pot/app.py ./app.py
CMD ["python", "app.py"]
