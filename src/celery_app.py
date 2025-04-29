import os
from celery import Celery
from dotenv import load_dotenv

# Load environment variables (e.g., for Redis URL)
load_dotenv()

# Get Redis URL from environment variable or use default
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Define Celery application instance
# The first argument is the name of the current module, important for autodiscovery of tasks.
# The second argument specifies the broker URL.
# The third argument specifies the backend URL (where results are stored).
celery_app = Celery(
    'neurozond_tasks', # Name of the Celery application
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=['src.tasks'] # List of modules where tasks are defined
)

# Optional configuration settings
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],  # Allow JSON content
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    # Configure result backend expiration (e.g., results expire after 1 day)
    result_expires=86400, 
    # Improve worker reliability
    task_acks_late=True,
    worker_prefetch_multiplier=1, # Process one task at a time per worker process
)

if __name__ == '__main__':
    # This allows running the worker directly using: python -m src.celery_app worker --loglevel=info
    # Although typically you'd run: celery -A src.celery_app worker --loglevel=info
    celery_app.start() 