import logging
from datetime import datetime
from pathlib import Path


def logger(info):
    # Configure log name
    log_path = 'logs/'
    current_date = datetime.now().strftime('%Y-%m-%d')  
    log_name = f'{log_path}/clnt_{current_date}.log'

    # Create log if it doesn't exist
    log_file = Path(f'{log_name}')
    log_file.parent.mkdir(exist_ok=True, parents=True)

    # Log info
    logging.basicConfig(filename=log_name, level=logging.INFO)
    logging.info(info)
