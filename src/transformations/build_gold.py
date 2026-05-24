from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count max as spark_max, sum as spark_sum, when

SILVER_DIR = Path("data/silver")
GOLD_DIR = Path("data/gold")

def get_spark():
    return (
        SparkSession.builder
        .appName("security-copilot-gold")
        .master("local[*]")
        .getOrCreate()
    )

def main():
    spark = get_spark()

    GOLD_DIR.mkdir(parents=True, exist_ok=True)