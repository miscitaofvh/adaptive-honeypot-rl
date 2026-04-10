FROM python:3.12-slim
WORKDIR /app
COPY base.py      /app/shared/honeypot_base.py
COPY fake_data.py /app/shared/fake_data.py
COPY cmdi_pot/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY cmdi_pot/app.py ./app.py
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "30", "--access-logfile", "-", "app:app"]
