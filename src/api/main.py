from Pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pyspark.sql.functions import col

from src.agents.investigate_alert import generate_investigation_report