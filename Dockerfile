# 1. Grab a lightweight computer with Python already installed
FROM python:3.9-slim

# 2. Create a filder inside the container named /app and work from there
WORKDIR /app

# 3. Copy packing list into the container
COPY requirements.txt .

# 4. Install those libraries inside the container
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy out actual processor script into the container 
COPY stream_processor.py .

# 6. The default command to run when someone turns the container on
CMD ["python", "stream_processor.py"]